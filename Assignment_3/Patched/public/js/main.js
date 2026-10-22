// Squeak! client - plain fetch(), no jQuery needed.

function postJson(url, body) {
  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }).then(function (res) { return res.json(); });
}

function getCsrfToken() {
  var meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.content : null;
}

function clearInvalid(el) {
  if (el) el.classList.remove('is-invalid');
}

document.addEventListener('DOMContentLoaded', function () {
  var signinForm = document.getElementById('signin-form');
  if (signinForm) {
    signinForm.addEventListener('submit', function (e) {
      e.preventDefault();
      var usernameEl = document.getElementById('signin-username');
      var passwordEl = document.getElementById('signin-password');
      clearInvalid(usernameEl);
      clearInvalid(passwordEl);

      postJson('/signin', {
        username: usernameEl.value,
        password: passwordEl.value,
      }).then(function (result) {
        if (result.success) {
          location.reload();
        } else {
          usernameEl.classList.add('is-invalid');
          passwordEl.classList.add('is-invalid');
        }
      });
    });
  }

  var signupForm = document.getElementById('signup-form');
  if (signupForm) {
    signupForm.addEventListener('submit', function (e) {
      e.preventDefault();
      var usernameEl = document.getElementById('signup-username');
      var passwordEl = document.getElementById('signup-password');
      var usernameError = document.getElementById('signup-username-error');
      var passwordError = document.getElementById('signup-password-error');

      clearInvalid(usernameEl);
      clearInvalid(passwordEl);
      usernameError.textContent = '';
      passwordError.textContent = '';

      postJson('/signup', {
        username: usernameEl.value,
        password: passwordEl.value,
      }).then(function (result) {
        if (result.success) {
          location.reload();
          return;
        }
        if (result.field === 'username') {
          usernameEl.classList.add('is-invalid');
          usernameError.textContent = 'Please choose a valid username.';
        } else {
          passwordEl.classList.add('is-invalid');
          passwordError.textContent = 'Please choose a valid password.';
        }
      });
    });
  }

  var signoutButton = document.getElementById('signout-button');
  if (signoutButton) {
    signoutButton.addEventListener('click', function () {
      postJson('/signout', { csrf_token: getCsrfToken() }).then(function () {
        location.reload();
      });
    });
  }
});
