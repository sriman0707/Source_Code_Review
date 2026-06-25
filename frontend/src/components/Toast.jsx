import React, { createContext, useContext, useState, useCallback } from 'react'
import { CheckCircle, XCircle, Info, X } from 'lucide-react'

const ToastContext = createContext(null)

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])

  const addToast = useCallback((message, type = 'info', duration = 4000) => {
    const id = Date.now()
    setToasts(prev => [...prev, { id, message, type }])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), duration)
  }, [])

  const removeToast = (id) => setToasts(prev => prev.filter(t => t.id !== id))

  return (
    <ToastContext.Provider value={addToast}>
      {children}
      <div className="toast-container">
        {toasts.map(({ id, message, type }) => (
          <div key={id} className={`toast ${type}`}>
            {type === 'success' && <CheckCircle size={16} color="var(--low)" />}
            {type === 'error' && <XCircle size={16} color="var(--critical)" />}
            {type === 'info' && <Info size={16} color="var(--accent)" />}
            <span style={{ flex: 1 }}>{message}</span>
            <button onClick={() => removeToast(id)} style={{ background: 'none', color: 'var(--text-muted)', padding: 0 }}>
              <X size={14} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export function useToast() {
  return useContext(ToastContext)
}
