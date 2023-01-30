import axios from 'axios';
import { useEffect, useState } from 'react';
import {
  BrowserRouter, Route, Routes
} from "react-router-dom";
import './App.css';

function App() {

  return (
    <div className="App">

      <BrowserRouter>

        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/signup" element={<SignUpPage />} />
        </Routes>
      </BrowserRouter>
    </div>
  );
}

function LoginPage() {

  return (
    <div>
      <form
        onSubmit={e => {
          e.preventDefault()

          const formData = new FormData(e.currentTarget)
          const uname = formData.get('uname')
          const pw = formData.get('pw')
          login(uname, pw)
            .then(res => {
              console.log(res)
              /**
               * 24/5/2022 daniel.kwok
               * On login success, save jwt to local storage, and redirect to home
               */
              if (res.success) {
                sessionStorage.setItem('x-demo-auth-access-token', res.accessToken)
                sessionStorage.setItem('x-demo-auth-refresh-token', res.refreshToken)
                window.location.pathname = '/'
              }
            })
            .catch(err => {
              alert(err?.toString())
            })
        }}
      >
        <h1>Sign In</h1>
        <input
          name="uname"
          placeholder='Username'
        />
        <input
          type='password'
          name="pw"
          placeholder='Password'
        />
        <button
          type='submit'
        >
          Sign in
        </button>
      </form>
      <p>
        New member? <a href='/signup'>Sign up here</a>
      </p>
    </div>
  )
}

function SignUpPage() {

  return (
    <form
      onSubmit={e => {
        e.preventDefault()

        const formData = new FormData(e.currentTarget)
        const uname = formData.get('uname')
        const pw = formData.get('pw')
        signup(uname, pw)
          .then(res => {
            if (res.success) {
              window.location.pathname = '/login'
            }
          })

      }}
    >
      <h1>Sign up</h1>
      <input
        name="uname"
        placeholder='Username'
      />
      <input
        type='password'
        name="pw"
        placeholder='Password'
      />
      <label htmlFor="isAdmin">Is admin?</label>
      <input
        type='checkbox'
        name="isAdmin"
      />
      <button
        type='submit'
      >
        Sign Up
      </button>
    </form >
  )
}


function HomePage() {

  const [profile, setProfile] = useState()

  useEffect(() => {
    getProfile()
      .then(res => setProfile(res?.user))
      .catch(err => console.log(`Get profile error`))
  }, [])

  return (
    profile ? (
      <>
        <h1>Hi, {profile?.username}</h1>
        <div>
          <button onClick={() => {
            signOut()
              .then(res => {
                if (res) {
                  /**
                   * 24/5/2022 daniel.kwok
                   * If logout success, remove jwt from session storage and redirect to login page
                   */
                  sessionStorage.removeItem('x-demo-auth-access-token')
                  sessionStorage.removeItem('x-demo-auth-refresh-token')
                  window.location.pathname = '/login'
                }
              })
          }}>
            Sign out
          </button>
        </div>
      </>
    ) : (
      null
    )
  )
}


/**********APIs**********/
const BASE_URL = 'http://localhost:4000'
const instance = axios.create({
  baseURL: BASE_URL
})

instance.interceptors.request.use(async (request) => {

  let token = sessionStorage.getItem('x-demo-auth-access-token')
  if (!token) return request

  const jwt = JSON.parse(atob(token.split('.')[1]));

  const {
    exp
  } = jwt

  const now = Math.floor(Date.now() / 1000)

  if (now >= exp) {
    console.log('Token is expired. Attempting to refresh access token via refresh token...') 
    await refreshAccessToken()
      .then(res => {
        console.log(`Successfully refreshed token.`)
        sessionStorage.setItem('x-demo-auth-access-token', res.data.accessToken)
        sessionStorage.setItem('x-demo-auth-refresh-token', res.data.refreshToken)
      })
      .catch(err => {
        console.log(`Failed to refresh token.`, err.response.data)

        sessionStorage.removeItem('x-demo-auth-access-token')
        sessionStorage.removeItem('x-demo-auth-refresh-token')

      })
  }

  token = sessionStorage.getItem('x-demo-auth-access-token')
  request.headers['Authorization'] = `Bearer ${token}`

  return request;
}, function (error) {
  console.log(`Request errored`)
  return Promise.reject(error);
});

instance.interceptors.response.use(function (response) {
  return response;
}, function (error) {
  if (error.response?.status === 401) {
    window.location.pathname = '/login'
  }

  return Promise.reject(error);
});


function login(uname, pw) {
  return instance.post('/login', {
    uname, pw
  })
    .then(res => {
      return res.data
    })
}

function signup(uname, pw) {
  return instance.post('/signup', {
    uname, pw
  })
    .then(res => {
      return res.data
    })
}

function signOut() {
  return instance.delete('/logout',)
    .then(res => {
      return res.data
    })
}

function getProfile() {
  return instance.get('/profile')
    .then(res => {
      return res.data
    })
}

function refreshAccessToken() {

  const AT = sessionStorage.getItem('x-demo-auth-access-token')
  const RT = sessionStorage.getItem('x-demo-auth-refresh-token')

  return axios.post(`${BASE_URL}/access-token`, null, {
    headers: {
      'x-demo-auth-access-token': `Bearer ${AT}`,
      'x-demo-auth-refresh-token': `Bearer ${RT}`
    }
  })

}

/**********APIs**********/

export default App;
