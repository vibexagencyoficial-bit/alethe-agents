import { useEffect } from 'react'

import { openControlPane } from '../lib/controlPaneOpen'
import { onControlPaneOpen } from '../lib/tauri'
import { useProjectsStore } from '../stores/projectsStore'

/**
 * Escuta o control plane: quando um cliente externo pede uma sessão, ela aparece na janela.
 *
 * Sem isto o spawn externo rodava invisível — o processo existia no `/terminals` e a tela não
 * mostrava nada, que foi o que o usuário viu ao dirigir o control plane por codex e outros
 * harnesses. O pane se liga à sessão que já existe (o `pty_id` vem no pedido), então a janela
 * mostra exatamente o processo que o cliente está dirigindo, sem subir um segundo.
 */
export function useControlPaneRequests(hydrated: boolean) {
  useEffect(() => {
    if (!hydrated) return
    let disposed = false

    const unlisten = onControlPaneOpen((request) => {
      if (disposed) return
      try {
        openControlPane(request, useProjectsStore.getState())
      } catch (error) {
        // Um pedido de pane que falha não pode derrubar a janela: a sessão continua viva no
        // control plane e o erro fica no console para quem estiver depurando.
        console.error('[control-pane] falha ao abrir o pane da sessão', error)
      }
    })

    return () => {
      disposed = true
      void unlisten.then((stop) => stop())
    }
  }, [hydrated])
}
