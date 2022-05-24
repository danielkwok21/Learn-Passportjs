import { useEffect, useState } from 'react';
import {
  BrowserRouter, Link, Navigate, Route, Routes
} from "react-router-dom";
import './App.css';

const BASE_URL = `http://localhost:4000`


function App() {

  const [isLoading, setIsLoading] = useState(true)
  const [isLoggedIn, setIsLoggedIn] = useState(false)

  useEffect(() => {
    verifySession()
  }, [])

  function verifySession() {
    setIsLoading(true)

    fetch(`${BASE_URL}/verify-session`, {
      method: 'POST',
      body: JSON.stringify({}),
      headers: {
        'Content-Type': 'application/json',
        'Authorization': localStorage.getItem('jwt')
      }
    })
      .then(res => res.json())
      .then(res => {
        if (res) {
          setIsLoggedIn(true)
        }
      })
      .catch(err => {
        setIsLoggedIn(false)

      })
      .finally(() => setIsLoading(false))
  }


  if (isLoading) {
    return <div></div>
  }

  return (
    <div className="App">
      <p>isLoggedIn: {isLoggedIn ? "true" : "false"}</p>

      {
        isLoggedIn ? (
          <ProtectedRoutes />
        ) : (
          <PublicRoutes />
        )
      }
    </div>
  );
}

/**STEP 2 */
function Login() {

  function onLogin(e) {
    e.preventDefault()

    const formData = new FormData(e.currentTarget)

    const body = Object.fromEntries(formData.entries())

    fetch(`${BASE_URL}/login`, {
      method: 'POST',
      body: JSON.stringify(body),
      headers: {
        'Content-Type': 'application/json'
      }
    })
      .then(res => res.json())
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

  }

  return (
    <form
      onSubmit={e => onLogin(e)}
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
/**STEP 1 */
function SignUp() {

  function onSignup(e) {
    e.preventDefault()

    const formData = new FormData(e.currentTarget)

    const body = Object.fromEntries(formData.entries())

    fetch(`${BASE_URL}/signup`, {
      method: 'POST',
      body: JSON.stringify(body),
      headers: {
        'Content-Type': 'application/json'
      }
    })
      .then(res => res.json())
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

  }

  return (
    <form
      onSubmit={e => onSignup(e)}
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
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<SignUp />} />
        {/* 
        24/5/2022 daniel.kwok
        If anything else, simply redirect to login.
        Used e.g. user tries to access a protected route, e.g. / or /profile
        */}
        <Route path="*" element={<Navigate to='/login' />} />
      </Routes>
    </BrowserRouter>
  )
}

/**STEP 3 */
function ProtectedRoutes() {

  function signOut() {

    fetch(`${BASE_URL}/logout`, {
      method: 'POST',
      body: JSON.stringify({}),
      headers: {
        'Content-Type': 'application/json',
        'Authorization': localStorage.getItem('jwt')
      }
    })
      .then(res => res.json())
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
  }

  return (
    <BrowserRouter>
      <div>
        <Link to="/">Home</Link>
        <Link to="/profile">Profile</Link>
        <button onClick={() => signOut()}>Sign out</button>
      </div>

      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/profile" element={<Profile />} />

        {/* 
        24/5/2022 daniel.kwok
        catch all for unknown page
        */}
        <Route path="*" element={<UnknownPage />} />
      </Routes>
    </BrowserRouter>
  )
}
function Home() {
  return <h1>Home</h1>
}
function Profile() {
  return <h1>Profile</h1>
}
function UnknownPage() {
  return <p>Unknown page. <a href='/'>Back to home</a></p>
}

export default App;
