/* Post-click verdict: once the victim frame has actually submitted and the
   ledger moved, say which technique this page is and what the click booked.

   The parent page cannot see pointer events that land inside a cross-origin
   iframe (verified: no pointerdown reaches the parent), so the trigger is the
   frame's own load sequence plus the victim's business state. */
(function () {
  "use strict";

  const cfg = window.__WS_VERDICT;
  if (!cfg) {
    return;
  }

  const card = document.getElementById("ws-verdict");
  const resultEl = document.getElementById("ws-verdict-result");
  const typeEl = document.getElementById("ws-verdict-type");
  const metaEl = document.getElementById("ws-verdict-meta");
  if (!card || !resultEl || !typeEl) {
    return;
  }

  const POLL_MS = 1000;
  const GIVE_UP_MS = 20000;
  let baseline = null;
  let armedAt = 0;
  let lastDescription = "";
  let timer = null;

  function yuan(cents) {
    return "¥" + (cents / 100).toFixed(2);
  }

  async function fetchState() {
    const url =
      "/demo/api/state?origin=" +
      encodeURIComponent(cfg.victimBase) +
      "&username=alice";
    const response = await fetch(url, { cache: "no-store" });
    if (!response.ok) {
      throw new Error("state " + response.status);
    }
    return response.json();
  }

  function describe(data) {
    const parts = [];
    const addedTransfers = data.transfers.slice(baseline ? baseline.transfers.length : 0);
    const addedGrants = data.grants.slice(baseline ? baseline.grants.length : 0);
    for (const transfer of addedTransfers) {
      parts.push(
        "扣款 " +
          yuan(transfer.amount_cents) +
          " → " +
          transfer.recipient +
          "（台账备注：" +
          (transfer.note || "—") +
          "）"
      );
    }
    for (const grant of addedGrants) {
      parts.push("新增第三方授权：" + grant.client_name);
    }
    return parts.join("；");
  }

  function render(text, tone) {
    card.hidden = false;
    card.dataset.tone = tone;
    resultEl.textContent = text;
  }

  function renderType() {
    typeEl.textContent = cfg.seq + " " + cfg.title;
    if (metaEl) {
      metaEl.textContent = cfg.keyComponent;
    }
  }

  async function tick() {
    if (!armedAt) {
      return;
    }
    let data = null;
    try {
      data = await fetchState();
    } catch (error) {
      if (Date.now() - armedAt > GIVE_UP_MS) {
        render("拿不到受害者状态，无法判定本次点击的结果。", "warn");
        armedAt = 0;
      }
      return;
    }
    const description = describe(data);
    if (description) {
      lastDescription = description;
      render(description, "ok");
    } else if (Date.now() - armedAt > GIVE_UP_MS) {
      render(
        "20 秒内台账没有变化：点击未命中目标按钮，或被当前防御档位拦截。",
        "warn"
      );
      armedAt = 0;
    }
  }

  function arm(reason) {
    armedAt = Date.now();
    lastDescription = "";
    render(reason, "pending");
    if (timer === null) {
      timer = window.setInterval(tick, POLL_MS);
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    renderType();
    const frame = document.getElementById("victim-frame");
    if (!frame) {
      return;
    }

    // The defense profile is a *global* hot-swap on the victim: switching it
    // in the split-screen demo silently changes every scenario page, and a
    // framing-blocking profile makes clicks look "dead". Say so here.
    const defenseChip = document.getElementById("ws-defense-chip");
    const warning = document.getElementById("ws-defense-warning");
    const warningText = document.getElementById("ws-defense-warning-text");
    const resetButton = document.getElementById("ws-defense-reset");

    function defenseUrl() {
      return (
        "/demo/api/defense?origin=" +
        encodeURIComponent(cfg.victimBase) +
        "&ancestor=" +
        encodeURIComponent(window.location.origin)
      );
    }

    function applyDefense(payload) {
      if (defenseChip) {
        defenseChip.textContent = payload.profile || "未知";
      }
      if (!warning || !warningText) {
        return;
      }
      if (payload.blocks_framing) {
        warning.hidden = false;
        warningText.textContent =
          "当前 victim 防御「" +
          payload.profile +
          "」会阻止本页嵌入（" +
          (payload.block_reason || "框架控制") +
          "）：iframe 里是浏览器的拦截页，点击不会到达目标。";
      } else {
        warning.hidden = true;
      }
    }

    async function refreshDefense() {
      try {
        const response = await fetch(defenseUrl(), { cache: "no-store" });
        applyDefense(await response.json());
      } catch (error) {
        if (defenseChip) {
          defenseChip.textContent = "读取失败";
        }
      }
    }

    if (resetButton) {
      resetButton.addEventListener("click", async function () {
        try {
          await fetch(defenseUrl(), {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ profile: "none" }),
          });
        } catch (error) {
          /* fall through to refresh */
        }
        await refreshDefense();
        frame.src = frame.src.split("#")[0] + "&_r=" + Date.now();
      });
    }

    refreshDefense();

    fetchState()
      .then(function (data) {
        baseline = data;
      })
      .catch(function () {
        baseline = null;
      });

    if (cfg.mutating === false) {
      card.hidden = false;
      card.dataset.tone = "warn";
      resultEl.textContent = "本页是探针：只检测能否嵌入，不诱导点击，不会有业务变化。";
      return;
    }

    let loads = 0;
    frame.addEventListener("load", function () {
      loads += 1;
      if (loads === 1) {
        return; // first load is just the target page rendering
      }
      arm("检测到 iframe 内发生跳转（表单已提交），正在核对受害者台账…");
    });
  });
})();
