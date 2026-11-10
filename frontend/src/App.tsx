import { useState } from 'react'
import type { FormEvent, ChangeEvent } from 'react'
import api from './api/axios'

interface TokenResponse {
  access: string
  refresh: string
}

function App() {
  const [username, setUsername] = useState<string>('')
  const [password, setPassword] = useState<string>('')

  async function handleLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()

    try {
      const response = await api.post<TokenResponse>('token/', {
        username,
        password,
      })

      const { access, refresh } = response.data

      localStorage.setItem('access_token', access)
      localStorage.setItem('refresh_token', refresh)

      console.log('JWT login successful')
    } catch (error) {
      console.error('Login failed:', error)
    }
  }

  async function getProfile() {
  try {
    const response = await api.get('me/')

    console.log('User profile:', response.data)
  } catch (error) {
    console.error('Failed to get profile:', error)
  }
}

async function handleLogout() {
  try {
    const refreshToken = localStorage.getItem('refresh_token')

    await api.post('token/logout/', {
      refresh: refreshToken,
    })

    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')

    console.log('Logged out successfully')
  } catch (error) {
    console.error('Logout failed:', error)
  }
}
  return (
    <div>
      <h1>Django Security Lab</h1>

      <form onSubmit={handleLogin}>
        <div>
          <label>Username</label>
          <input
            value={username}
            onChange={(event: ChangeEvent<HTMLInputElement>) =>
              setUsername(event.target.value)
            }
          />
        </div>

        <div>
          <label>Password</label>
          <input
            type="password"
            value={password}
            onChange={(event: ChangeEvent<HTMLInputElement>) =>
              setPassword(event.target.value)
            }
          />
        </div>

        <button type="submit">Login</button>
        <button type="button" onClick={getProfile}>
            Get My Profile
        </button>
        <button type="button" onClick={handleLogout}>
            Logout
        </button>
      </form>
    </div>
  )

}



export default App