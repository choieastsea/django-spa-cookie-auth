import React from 'react';

class App extends React.Component {
  constructor(props) {
    super(props);

    this.state = {
      csrf: '',
      username: '',
      password: '',
      error: '',
      isAuthenticated: false,
    };
  }

  componentDidMount = () => {
    this.getSession();
  };

  getCSRF = () => {
    fetch('http://localhost:8000/api/csrf/', {
      credentials: 'include',
    })
      .then((res) => {
        let csrfToken = res.headers.get('X-CSRFToken');
        this.setState({ csrf: csrfToken });
        console.log(`csrftoken : ${csrfToken}`);
      })
      .catch((err) => {
        console.log(err);
      });
  };

  getSession = () => {
    fetch('http://localhost:8000/api/session/', {
      credentials: 'include',
    })
      .then((res) => res.json())
      .then((data) => {
        console.log(data);
        if (data.isAuthenticated) {
          this.setState({ isAuthenticated: true });
        } else {
          this.setState({ isAuthenticated: false });
          this.getCSRF();
        }
      })
      .catch((err) => {
        console.log(err);
      });
  };

  //credential 없어도 되는 이유는 get이기 때문인가?
  whoami = () => {
    fetch('http://localhost:8000/api/whoami/', {
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'include',
    })
      .then((res) => res.json())
      .then((data) => {
        console.log('You are logged in as: ' + data.username);
      })
      .catch((err) => {
        console.log(err);
      });
  };

  handlePasswordChange = (event) => {
    this.setState({ password: event.target.value });
  };

  handleUserNameChange = (event) => {
    this.setState({ username: event.target.value });
  };

  isResponseOk(response) {
    if (response.status >= 200 && response.status <= 299) {
      return response.json();
    } else {
      throw Error(response.statusText);
    }
  }

  login = (event) => {
    event.preventDefault();
    fetch('http://localhost:8000/api/login/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': this.state.csrf,
      },
      credentials: 'include',
      body: JSON.stringify({ username: this.state.username, password: this.state.password }),
    })
      .then(this.isResponseOk)
      .then((data) => {
        console.log(data);
        this.setState({
          isAuthenticated: true,
          username: this.state.username,
          password: '',
          error: '',
        });
      })
      .catch((err) => {
        console.log(err);
        this.setState({ error: 'Wrong username or password.' });
      });
  };

  logout = () => {
    fetch('http://localhost:8000/api/logout', {
      credentials: 'include',
    })
      .then(this.isResponseOk)
      .then((data) => {
        console.log(data);
        this.setState({ isAuthenticated: false, username: '' });
        this.getCSRF();
      })
      .catch((err) => {
        console.log(err);
      });
  };
  onTest = () => {
    fetch('http://localhost:8000/api/csrf/', {
      credentials: 'include',
    })
      .then((res) => {
        let csrfToken = res.headers.get('X-CSRFToken');
        this.setState({ csrf: csrfToken });
        console.log(`csrftoken : ${csrfToken}`);
      })
      .catch((err) => {
        console.log(err);
      })
      .then(() => {
        fetch('http://localhost:8000/api/test/', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': this.state.csrf,
          },
          credentials: 'include',
        }).then((res) => {
          console.log(res);
        });
      });
  };
  render() {
    if (!this.state.isAuthenticated) {
      return (
        <div className="container mt-3">
          <h1>React Cookie Auth</h1>
          <br />
          <h2>Login</h2>
          <form onSubmit={this.login}>
            <div className="form-group">
              <label htmlFor="username">Username</label>
              <input
                type="text"
                className="form-control"
                id="username"
                name="username"
                value={this.state.username}
                onChange={this.handleUserNameChange}
              />
            </div>
            <div className="form-group">
              <label htmlFor="username">Password</label>
              <input
                type="password"
                className="form-control"
                id="password"
                name="password"
                value={this.state.password}
                onChange={this.handlePasswordChange}
              />
              <div>
                {this.state.error && <small className="text-danger">{this.state.error}</small>}
              </div>
            </div>
            <button type="submit" className="btn btn-primary">
              Login
            </button>
          </form>
          <button onClick={this.onTest} className="btn btn-secondary mt-2">test</button>
        </div>
      );
    }
    return (
      <div className="container mt-3">
        <h1>React Cookie Auth</h1>
        <p>Welcome {this.state.username}</p>
        <button className="btn btn-primary mr-2" onClick={this.whoami}>
          WhoAmI
        </button>
        <button className="btn btn-danger" onClick={this.logout}>
          Log out
        </button>
        <button onClick={this.onTest} className="btn btn-secondary ml-2">test</button>
      </div>
    );
  }
}

export default App;
