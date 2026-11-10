import axios from 'axios'

const api = axios.create({
  baseURL: '/api/',
})

let isRefreshing = false

let failedQueue: Array<{
  resolve: (token: string) => void
  reject: (error: unknown) => void
}> = []


function processQueue(error: unknown, token: string | null = null) {
  failedQueue.forEach((promise) => {
    if (error) {
      promise.reject(error)
    } else if (token) {
      promise.resolve(token)
    }
  })

  failedQueue = []
}

// Attach access token before every request
api.interceptors.request.use((config) => {
  const accessToken = localStorage.getItem('access_token')

  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`
  }

  return config
})

// Handle failed responses
api.interceptors.response.use(
  (response) => response,

  async (error) => {
    const originalRequest = error.config

    if (error.response?.status !== 401 || originalRequest._retry) {
      return Promise.reject(error)
    }

    originalRequest._retry = true

    // If another request is already refreshing, wait for it
    if (isRefreshing) {
      return new Promise((resolve, reject) => {
        failedQueue.push({ resolve, reject })
      }).then((token) => {
        originalRequest.headers.Authorization = `Bearer ${token}`
        return api(originalRequest)
      })
    }

    isRefreshing = true

    try {
      const refreshToken = localStorage.getItem('refresh_token')

      if (!refreshToken) {
        throw new Error('No refresh token available')
      }

      const response = await axios.post('/api/token/refresh/', {
        refresh: refreshToken,
      })

      const newAccessToken = response.data.access
      const newRefreshToken = response.data.refresh

      localStorage.setItem('access_token', newAccessToken)
      localStorage.setItem('refresh_token', newRefreshToken)

      // Release all waiting requests
      processQueue(null, newAccessToken)

      originalRequest.headers.Authorization = `Bearer ${newAccessToken}`

      return api(originalRequest)

    } catch (refreshError) {
      processQueue(refreshError)

      localStorage.removeItem('access_token')
      localStorage.removeItem('refresh_token')

      return Promise.reject(refreshError)

    } finally {
      isRefreshing = false
    }
  }
)

export default api