// Limite de concorrência do listener local (Task 2 do plano alethe-circuito-completo).
//
// O listener atende por um único laço de `accept` (`agent_events::accept_loop`). Enquanto o
// handler rodava inline nesse laço, um pedido lento — os caminhos de git e do gateway usam
// `block_on` — travava o aceite da próxima conexão e, junto com ele, o
// `GET /control/v1/health` de todos os clientes.
//
// Aqui mora só o limite: quem for despachar um pedido reserva uma vaga antes de subir a
// thread e a devolve quando a thread termina, inclusive se ela entrar em pânico. Uma vaga
// que não sai dentro de `wait` vira `None`, e o chamador responde 503 na hora: uma espera
// longa dentro do control plane é exatamente o que esta tarefa veio remover.

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Quantos pedidos o listener processa ao mesmo tempo. Um pedido lento ocupa uma vaga e as
/// outras seguem livres para `/health`, que é curto por natureza.
pub const DEFAULT_REQUEST_LIMIT: usize = 16;

/// Espera máxima por uma vaga antes de recusar o pedido. Curta de propósito: o cliente ouve
/// "volte depois" rápido em vez de acumular espera.
pub const DEFAULT_ACQUIRE_WAIT: Duration = Duration::from_millis(250);

pub struct RequestPool {
    limit: usize,
    wait: Duration,
    active: Mutex<usize>,
    released: Condvar,
}

/// Vaga reservada no pool. Carrega um `Arc` do pool (e não uma referência) porque a thread do
/// pedido precisa da vaga por tempo indeterminado; o `Drop` devolve o slot.
pub struct Permit {
    pool: Arc<RequestPool>,
}

impl RequestPool {
    pub fn new(limit: usize) -> Self {
        Self::with_wait(limit, DEFAULT_ACQUIRE_WAIT)
    }

    pub fn with_wait(limit: usize, wait: Duration) -> Self {
        Self {
            // Um limite zero deixaria o listener mudo para sempre; o mínimo é uma vaga.
            limit: limit.max(1),
            wait,
            active: Mutex::new(0),
            released: Condvar::new(),
        }
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Quantos pedidos estão em processamento agora.
    pub fn active(&self) -> usize {
        *self.lock_active()
    }

    /// Reserva uma vaga esperando até `wait`. `None` = pool saturado nesse prazo.
    pub fn acquire(self: &Arc<Self>) -> Option<Permit> {
        let deadline = Instant::now() + self.wait;
        let mut active = self.lock_active();
        loop {
            if *active < self.limit {
                *active += 1;
                return Some(Permit {
                    pool: Arc::clone(self),
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let (guard, _) = self
                .released
                .wait_timeout(active, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            active = guard;
        }
    }

    fn lock_active(&self) -> std::sync::MutexGuard<'_, usize> {
        self.active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn release(&self) {
        {
            let mut active = self.lock_active();
            *active = active.saturating_sub(1);
        }
        self.released.notify_one();
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.pool.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    #[test]
    fn acquire_goes_up_to_the_limit_and_then_sheds() {
        let pool = Arc::new(RequestPool::with_wait(2, Duration::from_millis(60)));
        let first = pool.acquire().expect("primeira vaga");
        let second = pool.acquire().expect("segunda vaga");
        assert_eq!(pool.active(), 2);

        let start = Instant::now();
        assert!(pool.acquire().is_none(), "terceira vaga passaria do limite");
        let waited = start.elapsed();
        assert!(
            waited >= Duration::from_millis(50) && waited < Duration::from_millis(600),
            "a espera pelo slot deveria ser limitada pelo wait do pool, foi {waited:?}"
        );

        drop(first);
        assert_eq!(pool.active(), 1);
        let third = pool.acquire().expect("vaga liberada deve ser reaproveitada");
        assert_eq!(pool.active(), 2);
        drop((second, third));
        assert_eq!(pool.active(), 0);
    }

    #[test]
    fn a_saturated_pool_hands_the_slot_to_a_waiter() {
        let pool = Arc::new(RequestPool::with_wait(1, Duration::from_millis(2000)));
        let held = pool.acquire().expect("vaga principal");
        let waiter_pool = Arc::clone(&pool);
        let (sender, receiver) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let permit = waiter_pool.acquire();
            sender.send(permit.is_some()).expect("sinalizar vaga");
            permit
        });

        // O waiter fica parado no condvar enquanto a vaga está tomada.
        assert!(receiver.recv_timeout(Duration::from_millis(150)).is_err());
        drop(held);
        assert!(receiver.recv_timeout(Duration::from_millis(1000)).expect("waiter acordou"));
        assert_eq!(pool.active(), 1);
        drop(waiter.join().expect("join waiter"));
        assert_eq!(pool.active(), 0);
    }

    #[test]
    fn a_panicking_task_still_returns_its_slot() {
        let pool = Arc::new(RequestPool::with_wait(1, Duration::from_millis(100)));
        let task_pool = Arc::clone(&pool);
        let task = std::thread::spawn(move || {
            let _permit = task_pool.acquire().expect("vaga da task");
            panic!("task morre no meio");
        });
        assert!(task.join().is_err(), "a task deveria ter entrado em panico");

        let permit = pool.acquire().expect("slot devolvido no Drop do permit");
        assert_eq!(pool.active(), 1);
        drop(permit);
        assert_eq!(pool.active(), 0);
    }

    #[test]
    fn slots_run_in_parallel_up_to_the_limit() {
        let limit = 4;
        let pool = Arc::new(RequestPool::with_wait(limit, Duration::from_millis(120)));
        let inside = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..limit {
            let task_pool = Arc::clone(&pool);
            let inside = Arc::clone(&inside);
            let peak = Arc::clone(&peak);
            tasks.push(std::thread::spawn(move || {
                let _permit = task_pool.acquire().expect("vaga da task");
                let now_inside = inside.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now_inside, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(400));
                inside.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        std::thread::sleep(Duration::from_millis(120));
        assert!(
            pool.acquire().is_none(),
            "com as {limit} vagas ocupadas o pool tem que recusar"
        );
        for task in tasks {
            task.join().expect("join task");
        }
        assert_eq!(
            peak.load(Ordering::SeqCst),
            limit,
            "um pool com {limit} vagas que serializa deixaria o pico em 1"
        );
        assert!(pool.acquire().is_some(), "as vagas voltam quando as tasks saem");
    }

    #[test]
    fn a_zero_limit_is_promoted_to_one_slot() {
        let pool = Arc::new(RequestPool::new(0));
        assert_eq!(pool.limit(), 1);
        let permit = pool.acquire().expect("o listener nunca fica sem vaga");
        assert!(pool.acquire().is_none());
        drop(permit);
        assert!(pool.acquire().is_some());
    }
}
