import { useEffect, useState } from 'react';
import './App.css';

function login() {
  const body = {
    uname: 'danielkwok',
    pw: '123456'
  }

  fetch(`http://localhost:4000/login`, {
    method: 'POST',
    body: JSON.stringify(body),
    credentials: 'include'
  })
    .then(res => res.json())
}

function getData() {
  return fetch(`http://localhost:4000/protected-routes`, {
    method: 'GET',
    credentials: 'include'
  })
    .then(res => res.json())
}

function App() {

  const [result, setResult] = useState({
    data: ''
  })

  useEffect(() => {
    getData()
      .then(results => setResult(results))
  }, [])

  return (
    <div className="App">
      <p>
        {
          JSON.stringify(result)
        }
      </p>
      <button onClick={() => login()}>
        Login
      </button>
    </div>
  );
}

export default App;
