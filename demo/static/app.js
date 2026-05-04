// SQL Shield Demo -- Client-side JavaScript

// ==================================================================
// PAGE NAVIGATION
// ==================================================================

function showSection(name, clickedLink) {
  // Hide all sections, then show the requested one
  var sections = document.querySelectorAll('.section');
  for (var i = 0; i < sections.length; i++) {
    sections[i].classList.remove('active');
  }
  var target = document.getElementById('section-' + name);
  if (target) {
    target.classList.add('active');
  }

  // Update the active nav link
  var links = document.querySelectorAll('.nav-link');
  for (var i = 0; i < links.length; i++) {
    links[i].classList.remove('active');
  }
  if (clickedLink) {
    clickedLink.classList.add('active');
  }

  // Hide the info panels when switching pages
  hideQueryDisplay();
  hideShieldPanel();
}


// ==================================================================
// SQL QUERY DISPLAY
// ==================================================================

function showQueryDisplay(queryString) {
  if (!queryString) return;
  var container = document.getElementById('query-display');
  var text      = document.getElementById('query-text');
  text.textContent = queryString;
  container.classList.remove('hidden');
}

function hideQueryDisplay() {
  document.getElementById('query-display').classList.add('hidden');
}


// ==================================================================
// SHIELD RESULT PANEL
// ==================================================================
// When Shield is ON, we show the verdict and what each stage found

function showShieldPanel(shieldResult) {
  if (!shieldResult) {
    hideShieldPanel();
    return;
  }

  var panel   = document.getElementById('shield-panel');
  var header  = document.getElementById('shield-panel-header-el');
  var icon    = document.getElementById('shield-panel-icon');
  var verdict = document.getElementById('shield-panel-verdict');
  var stages  = document.getElementById('shield-panel-stages');

  // Set the header color and text based on verdict
  header.className = 'shield-panel-header ' + shieldResult.verdict;

  if (shieldResult.verdict === 'accepted') {
    icon.textContent = '\u2714';   // checkmark
    verdict.textContent = 'SHIELD: ACCEPTED -- input is safe';
  } else if (shieldResult.verdict === 'suspicious') {
    icon.textContent = '\u26A0';   // warning
    verdict.textContent = 'SHIELD: SUSPICIOUS -- input flagged for review';
  } else {
    icon.textContent = '\u2716';   // X mark
    verdict.textContent = 'SHIELD: REJECTED -- input blocked';
  }

  // Build the stage details
  stages.innerHTML = '';
  for (var i = 0; i < shieldResult.stages.length; i++) {
    var s = shieldResult.stages[i];
    var line = document.createElement('div');
    line.className = 'stage-line';
    line.innerHTML =
      '<span class="stage-name">' + s.stage + ':</span>' +
      '<span class="stage-verdict ' + s.verdict + '">' + s.verdict + '</span>' +
      '<span class="stage-detail">' + escapeHtml(s.detail) + '</span>';
    stages.appendChild(line);
  }

  panel.classList.remove('hidden');
}

function hideShieldPanel() {
  document.getElementById('shield-panel').classList.add('hidden');
}


// ==================================================================
// SHIELD TOGGLE
// ==================================================================

function toggleShield() {
  var checkbox = document.getElementById('shield-toggle');
  var label    = document.getElementById('shield-label');
  var enabled  = checkbox.checked;

  if (enabled) {
    label.textContent = 'Shield ON';
    label.className = 'shield-label on';
  } else {
    label.textContent = 'Shield OFF';
    label.className = 'shield-label off';
  }

  // Tell the server
  postJSON('/api/shield/toggle', { enabled: enabled }, function () {
    if (enabled) {
      postJSON('/api/shield/reset', {}, function () {});
    }
  });
}


// ==================================================================
// HELPER: send a POST request and call back with the JSON response
// ==================================================================

function postJSON(url, payload, callback) {
  var xhr = new XMLHttpRequest();
  xhr.open('POST', url, true);
  xhr.setRequestHeader('Content-Type', 'application/json');
  xhr.onload = function () {
    if (xhr.status === 200) {
      var data = JSON.parse(xhr.responseText);
      callback(data);
    }
  };
  xhr.send(JSON.stringify(payload));
}


// ==================================================================
// SEARCH
// ==================================================================

function handleSearch(event) {
  event.preventDefault();

  var query = document.getElementById('search-input').value.trim();
  if (!query) return false;

  // Switch to Home section and highlight the Home nav link
  var homeLink = document.querySelector('.nav-link');
  showSection('home', homeLink);

  postJSON('/api/search', { query: query }, function (data) {

    showQueryDisplay(data.query);
    showShieldPanel(data.shield);

    var container = document.getElementById('search-results');
    var list      = document.getElementById('search-results-list');
    var count     = document.getElementById('result-count');

    list.innerHTML = '';

    if (data.blocked) {
      list.innerHTML = '<div class="blocked-banner">Request blocked by Shield. No query was executed.</div>';
      count.textContent = '';
      container.classList.remove('hidden');
      return;
    }

    count.textContent = '(' + data.result_count + ' found)';

    for (var i = 0; i < data.results.length; i++) {
      var product = data.results[i];
      var card = document.createElement('div');
      card.className = 'result-card';
      card.innerHTML =
        '<span class="r-name">' + escapeHtml(product.name) + '</span>' +
        '<span class="r-price">$' + product.price + '</span>' +
        '<span class="r-desc">' + escapeHtml(product.description) + '</span>';
      list.appendChild(card);
    }

    container.classList.remove('hidden');
  });

  return false;
}


// ==================================================================
// LOGIN
// ==================================================================

function handleLogin(event) {
  event.preventDefault();

  var username = document.getElementById('login-user').value;
  var password = document.getElementById('login-pass').value;

  postJSON('/api/login', { username: username, password: password }, function (data) {

    showQueryDisplay(data.query);
    showShieldPanel(data.shield);

    var msg = document.getElementById('login-msg');

    if (data.blocked) {
      msg.style.color = 'var(--red)';
      msg.textContent = data.message;
      return;
    }

    if (data.success) {
      msg.style.color = 'var(--green)';
    } else {
      msg.style.color = 'var(--red)';
    }
    msg.textContent = data.message;
  });

  return false;
}


// ==================================================================
// CONTACT FORM
// ==================================================================

function handleContact(event) {
  event.preventDefault();

  var name    = document.getElementById('contact-name').value;
  var email   = document.getElementById('contact-email').value;
  var message = document.getElementById('contact-msg').value;

  postJSON('/api/contact', { name: name, email: email, message: message }, function (data) {

    showQueryDisplay(data.query);
    showShieldPanel(data.shield);

    var el = document.getElementById('contact-result');

    if (data.blocked) {
      el.style.color = 'var(--red)';
      el.textContent = data.message;
      return;
    }

    if (data.success) {
      el.style.color = 'var(--green)';
    } else {
      el.style.color = 'var(--red)';
    }
    el.textContent = data.message;
  });

  return false;
}


// ==================================================================
// CHATBOT
// ==================================================================

function toggleChat() {
  var widget = document.getElementById('chat-widget');
  var icon   = document.getElementById('chat-toggle-icon');

  widget.classList.toggle('collapsed');
  icon.textContent = widget.classList.contains('collapsed') ? '+' : '\u2212';
}

function handleChat(event) {
  event.preventDefault();

  var input = document.getElementById('chat-input');
  var text  = input.value.trim();
  if (!text) return false;

  appendChatMessage('user', text);
  input.value = '';

  postJSON('/api/chat', { message: text }, function (data) {

    if (data.blocked) {
      appendChatMessage('blocked', 'SHIELD BLOCKED: ' + data.shield.verdict);
      appendChatMessage('bot', data.reply);
    } else {
      if (data.query) appendChatMessage('query', 'SQL: ' + data.query);
      appendChatMessage('bot', data.reply);
    }

    if (data.query) showQueryDisplay(data.query);
    showShieldPanel(data.shield);
  });

  return false;
}

function appendChatMessage(role, text) {
  var container = document.getElementById('chat-messages');
  var div = document.createElement('div');
  div.className = 'chat-msg ' + role;
  div.textContent = text;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}


// ==================================================================
// EXAMPLE CLICK-TO-TRY
// ==================================================================

function handleExampleClick(el) {
  var fill    = el.dataset.fill;
  var payload = el.dataset.payload;
  if      (fill === 'search')  fillSearch(payload);
  else if (fill === 'login')   fillLogin(payload);
  else if (fill === 'contact') fillContact(payload);
  else if (fill === 'chat')    fillChat(payload);
}

function fillSearch(text) {
  var homeLink = document.querySelector('.nav-link');
  showSection('home', homeLink);
  var input = document.getElementById('search-input');
  input.value = text;
  input.focus();
}

function fillLogin(text) {
  var loginLink = document.querySelectorAll('.nav-link')[1];
  showSection('login', loginLink);
  var input = document.getElementById('login-user');
  input.value = text;
  input.focus();
}

function fillContact(text) {
  var contactLink = document.querySelectorAll('.nav-link')[2];
  showSection('contact', contactLink);
  var input = document.getElementById('contact-name');
  input.value = text;
  input.focus();
}

function fillChat(text) {
  var widget = document.getElementById('chat-widget');
  if (widget.classList.contains('collapsed')) {
    toggleChat();
  }
  var input = document.getElementById('chat-input');
  input.value = text;
  input.focus();
}


// ==================================================================
// UTILITY
// ==================================================================

function escapeHtml(str) {
  var div = document.createElement('div');
  div.appendChild(document.createTextNode(str));
  return div.innerHTML;
}
