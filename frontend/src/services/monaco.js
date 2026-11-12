// Bundle Monaco with the app instead of fetching it from a CDN, so Patch Review works offline.
import * as monaco from 'monaco-editor/editor/editor.api'
import 'monaco-editor/languages/definitions/java/register'
import EditorWorker from 'monaco-editor/editor/editor.worker?worker'
import { loader } from '@monaco-editor/react'

self.MonacoEnvironment = { getWorker: () => new EditorWorker() }
loader.config({ monaco })
