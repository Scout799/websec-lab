/* Shared browser-side event reporting for attacker scenarios. */
(function () {
  "use strict";

  function reportEvent(runId, token, event) {
    if (!runId || !token || !event || !event.type) {
      return Promise.resolve(false);
    }
    return fetch("/api/runs/" + encodeURIComponent(runId) + "/events", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Websec-Test-Token": token
      },
      body: JSON.stringify(event),
      keepalive: true
    })
      .then(function (response) {
        return response.ok;
      })
      .catch(function () {
        return false;
      });
  }

  window.AttackReport = { reportEvent: reportEvent };
})();
