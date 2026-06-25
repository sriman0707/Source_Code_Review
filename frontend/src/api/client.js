import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const api = axios.create({
  baseURL: API_URL,
  headers: { 'Content-Type': 'application/json' },
})

// Attach JWT from localStorage
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// Handle 401 — auto-logout
api.interceptors.response.use(
  (res) => res,
  async (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('access_token')
      localStorage.removeItem('user')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

// ─── Auth ─────────────────────────────────────────────────────
export const authAPI = {
  login: (username, password) =>
    api.post('/api/v1/auth/login', new URLSearchParams({ username, password }), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    }),
  register: (data) => api.post('/api/v1/auth/register', data),
  me: () => api.get('/api/v1/auth/me'),
}

// ─── Scans ────────────────────────────────────────────────────
export const scansAPI = {
  upload: (formData) =>
    api.post('/api/v1/scans/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    }),
  scanGitHub: (formData) =>
    api.post('/api/v1/scans/github', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    }),
  list: (params) => api.get('/api/v1/scans', { params }),
  get: (id) => api.get(`/api/v1/scans/${id}`),
  cancel: (id) => api.delete(`/api/v1/scans/${id}`),
}

// ─── Findings ─────────────────────────────────────────────────
export const findingsAPI = {
  getByScan: (scanId, params) => api.get(`/api/v1/findings/scan/${scanId}`, { params }),
  get: (id) => api.get(`/api/v1/findings/${id}`),
  update: (id, data) => api.patch(`/api/v1/findings/${id}`, data),
}

// ─── Dashboard ────────────────────────────────────────────────
export const dashboardAPI = {
  summary: () => api.get('/api/v1/dashboard/summary'),
  trends: (days) => api.get('/api/v1/dashboard/trends', { params: { days } }),
  topFindings: (limit) => api.get('/api/v1/dashboard/top-findings', { params: { limit } }),
  cweBreakdown: () => api.get('/api/v1/dashboard/cwe-breakdown'),
}

export default api
