import { useEffect, useState } from 'react';
import {
  BrowserRouter, Link, Route, Routes
} from "react-router-dom";
import axios from 'axios'
import './App.css';

function App() {

  return (
    <div className="App">
      <ProtectedRoutes />
      <PublicRoutes />
    </div>
  );
}

function LoginPage() {

  return (
    <form
      onSubmit={e => {
        e.preventDefault()

        const formData = new FormData(e.currentTarget)
        login(formData)
          .then(res => {
            /**
             * 24/5/2022 daniel.kwok
             * On login success, save jwt to local storage, and redirect to home
             */
            if (res.success) {
              localStorage.setItem('jwt', res.token)
              window.location.pathname = '/'
            }
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
  )
}

function SignUpPage() {

  return (
    <form
      onSubmit={e => {
        e.preventDefault()

        const formData = new FormData(e.currentTarget)
        signup(formData)
          .then(res => {
            if (res.success) {
              /**
               * 24/5/2022 daniel.kwok
               * On sign up success, save jwt to local storage, and redirect to home
               */
              localStorage.setItem('jwt', res.token)
              window.location.pathname = '/'
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

function PublicRoutes() {

  return (
    <BrowserRouter>
      <div>
        <Link to="/login">Login</Link>
        <Link to="/signup">Signup</Link>
      </div>

      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/signup" element={<SignUpPage />} />
      </Routes>
    </BrowserRouter>
  )
}

function ProtectedRoutes() {

  const [profile, setProfile] = useState()

  useEffect(() => {
    getProfile()
      .then(res => setProfile(res.profile))
  }, [])

  return (
    <BrowserRouter>
      <h1>Hi, {profile?.username}</h1>
      <div>
        <Link to="/">Home</Link>
        <Link to="/profile">Profile</Link>
        <button onClick={() => {
          signOut()
            .then(res => {
              if (res) {
                /**
                 * 24/5/2022 daniel.kwok
                 * If logout success, remove jwt from local storage and redirect to login page
                 */
                localStorage.removeItem('jwt')
                window.location.pathname = '/login'
              }
            })
        }}>
          Sign out
        </button>
      </div>

      <Routes>
        <Route path="/" element={<HomePage />} />
        <Route path="/profile" element={<ProfilePage />} />

        {/* 
        24/5/2022 daniel.kwok
        catch all for unknown page
        */}
        <Route path="*" element={<UnknownPage />} />
      </Routes>
    </BrowserRouter>
  )
}

function HomePage() {
  return <h1>Home</h1>
}
function ProfilePage() {
  return <h1>Profile</h1>
}
function UnknownPage() {
  return <p>Unknown page. <a href='/'>Back to home</a></p>
}

/**********APIs**********/
const instance = axios.create({
  baseURL: 'http://localhost:4000',
  headers: {
    'Content-Type': 'application/json'
  }
})
const BASE_URL = 'http://localhost:4000'

function login(formData) {

  return instance.post('/login', {
    data: formData,
  })
    .then(res => {
      console.log(res)
      return res.data
    })
}

function signup(formData) {

  const body = Object.fromEntries(formData.entries())

  return fetch(`${BASE_URL}/signup`, {
    method: 'POST',
    body: JSON.stringify(body),
    headers: {
      'Content-Type': 'application/json'
    }
  })
    .then(res => res.json())
}

function signOut() {
  return fetch(`${BASE_URL}/logout`, {
    method: 'POST',
    body: JSON.stringify({}),
    headers: {
      'Content-Type': 'application/json',
      'Authorization': localStorage.getItem('jwt')
    }
  })
    .then(res => res.json())
}

function getProfile() {
  return fetch(`${BASE_URL}/profile`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': localStorage.getItem('jwt')
    }
  })
    .then(res => res.json())
}


export default App;
