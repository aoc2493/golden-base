(function () {
  "use strict";

  var FEATURE = "demo.echo";
  var SKU = "demo_echo";

  var $ = function (id) { return document.getElementById(id); };

  function log(message, data) {
    var line = new Date().toLocaleTimeString() + "  " + message;
    if (data !== undefined) {
      line += "\n" + JSON.stringify(data, null, 2);
    }
    var box = $("log");
    box.textContent = line + "\n\n" + box.textContent;
    box.scrollTop = 0;
  }

  function setState(id, text, kind) {
    var el = $(id);
    el.textContent = text;
    el.className = "state" + (kind ? " " + kind : "");
  }

  async function api(path, options) {
    var init = options || {};
    init.credentials = "same-origin";
    if (init.body && typeof init.body !== "string") {
      init.headers = Object.assign({ "Content-Type": "application/json" }, init.headers || {});
      init.body = JSON.stringify(init.body);
    }
    var resp = await fetch(path, init);
    var payload = await resp.json();
    if (payload.code !== 0) {
      throw new Error(payload.msg || ("request failed: " + resp.status));
    }
    return payload.data;
  }

  function credentials() {
    return {
      email: ($("email").value || "").trim(),
      password: $("password").value || ""
    };
  }

  $("btn-register").addEventListener("click", async function () {
    try {
      var data = await api("/api/auth/email/register", { method: "POST", body: credentials() });
      setState("account-state", "Signed in as user #" + data.user_id, "ok");
      log("registered", data);
    } catch (err) {
      setState("account-state", err.message, "err");
      log("register failed: " + err.message);
    }
  });

  $("btn-login").addEventListener("click", async function () {
    try {
      var data = await api("/api/auth/email/login", { method: "POST", body: credentials() });
      setState("account-state", "Signed in as user #" + data.user_id, "ok");
      log("logged in", data);
    } catch (err) {
      setState("account-state", err.message, "err");
      log("login failed: " + err.message);
    }
  });

  $("btn-logout").addEventListener("click", async function () {
    try {
      await api("/api/auth/logout", { method: "POST" });
      setState("account-state", "Not signed in.");
      setState("demo-state", "No purchase yet.");
      log("logged out");
    } catch (err) {
      log("logout failed: " + err.message);
    }
  });

  $("btn-products").addEventListener("click", async function () {
    try {
      var data = await api("/api/product/list");
      var body = $("products").querySelector("tbody");
      body.textContent = "";
      data.list.forEach(function (p) {
        var tr = document.createElement("tr");
        [p.sku_code, p.name, p.product_type, p.price.toFixed(2)].forEach(function (value) {
          var td = document.createElement("td");
          td.textContent = String(value);
          tr.appendChild(td);
        });
        body.appendChild(tr);
      });
      log("products loaded: " + data.list.length);
    } catch (err) {
      log("load products failed: " + err.message);
    }
  });

  $("btn-buy").addEventListener("click", async function () {
    var text = ($("demo-text").value || "").trim();
    if (!text) {
      setState("demo-state", "Enter some text first.", "err");
      return;
    }
    $("btn-buy").disabled = true;
    try {
      var order = await api("/api/order/create", {
        method: "POST",
        body: { sku_code: SKU, channel: "wechat", biz_data: { text: text } }
      });
      log("order created", order);
      var paid = await api("/api/payment/mock/pay", {
        method: "POST",
        body: { order_no: order.order_no }
      });
      setState("demo-state", "Paid order " + order.order_no + " · status " + paid.status, "ok");
      log("mock payment done", paid);
    } catch (err) {
      setState("demo-state", err.message, "err");
      log("purchase failed: " + err.message);
    } finally {
      $("btn-buy").disabled = false;
    }
  });

  $("btn-check").addEventListener("click", async function () {
    var text = ($("demo-text").value || "").trim();
    if (!text) {
      setState("demo-state", "Enter some text first.", "err");
      return;
    }
    try {
      var data = await api("/api/entitlement/check", {
        method: "POST",
        body: { feature: FEATURE, sides: [text] }
      });
      setState("demo-state", data.allowed ? "Unlocked." : "Locked — buy first.", data.allowed ? "ok" : "err");
      log("entitlement", data);
    } catch (err) {
      setState("demo-state", err.message, "err");
      log("check failed: " + err.message);
    }
  });

  $("btn-echo").addEventListener("click", async function () {
    var text = ($("demo-text").value || "").trim();
    if (!text) {
      setState("demo-state", "Enter some text first.", "err");
      return;
    }
    try {
      var data = await api("/api/demo/echo", { method: "POST", body: { text: text } });
      setState("demo-state", "Echo: " + data.text, "ok");
      log("demo API result", data);
    } catch (err) {
      setState("demo-state", err.message, "err");
      log("demo API failed: " + err.message);
    }
  });
})();
