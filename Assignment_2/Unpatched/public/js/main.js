// @home client — talks to the server purely via AJAX (fetch)

var lightIds = [
  ["kitchen", "stove"],
  ["kitchen", "ceiling"],
  ["livingroom", "sofa"],
  ["livingroom", "ceiling"],
  ["bedroom", "bed"],
  ["bedroom", "ceiling"],
];

var temperatureRooms = ["kitchen", "livingroom", "bedroom"];

function lightElementId(room, light) {
  return room + "-lights-" + light;
}

function temperatureElementId(room) {
  return room + "-temperature";
}

function updateLightButton(room, light, on) {
  var el = document.getElementById(lightElementId(room, light));
  if (!el) return;
  el.classList.remove("btn-secondary", "btn-warning");
  el.classList.add(on ? "btn-warning" : "btn-secondary");
}

function updateTemperature(room, temperature) {
  var el = document.getElementById(temperatureElementId(room));
  if (!el) return;
  el.textContent = temperature + " °C";
}

function refreshLight(room, light) {
  fetch("/" + room + "/lights/" + light)
    .then(function (res) { return res.json(); })
    .then(function (state) { updateLightButton(room, light, state.on); })
    .catch(function (err) { console.error("refreshLight failed", err); });
}

function refreshTemperature(room) {
  fetch("/" + room + "/temperature")
    .then(function (res) { return res.json(); })
    .then(function (state) { updateTemperature(room, state.temperature); })
    .catch(function (err) { console.error("refreshTemperature failed", err); });
}

function refreshAll() {
  lightIds.forEach(function (pair) { refreshLight(pair[0], pair[1]); });
  temperatureRooms.forEach(function (room) { refreshTemperature(room); });
}

function clickLight(room, light) {
  fetch("/" + room + "/lights/" + light, { method: "POST" })
    .then(function (res) { return res.json(); })
    .then(function (state) { updateLightButton(room, light, state.on); })
    .catch(function (err) { console.error("clickLight failed", err); });
}

function wireUpButtons() {
  lightIds.forEach(function (pair) {
    var room = pair[0], light = pair[1];
    var el = document.getElementById(lightElementId(room, light));
    if (!el) return;
    el.addEventListener("click", function () { clickLight(room, light); });
  });

  var logoutBtn = document.getElementById("logout-button");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", function () {
      fetch("/logout", { method: "POST" }).then(function () {
        window.location.href = "/login";
      });
    });
  }
}

document.addEventListener("DOMContentLoaded", function () {
  wireUpButtons();
  refreshAll();
  setInterval(refreshAll, 5000);
});
