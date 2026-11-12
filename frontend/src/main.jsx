import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import App from './App'
import { WorkspaceProvider } from './services/workspace'
import './styles.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <WorkspaceProvider>
        <App />
      </WorkspaceProvider>
      <Toaster position="bottom-right" toastOptions={{ style: { background: '#172338', color: '#e5edf8', border: '1px solid #2a3a52' } }} />
    </BrowserRouter>
  </React.StrictMode>,
)
