'use strict';

function emit(kind, data) {
  try {
    console.log('SAT_EVENT ' + JSON.stringify({ kind: kind, data: data, ts: Date.now() }));
  } catch (_) {}
}

function safeUrl(value) {
  if (value === null || value === undefined) return null;
  var s = String(value);
  return s.replace(/([?#]).*$/, '$1<redacted>');
}

function safeIntent(intent) {
  try {
    var data = intent.getData();
    return {
      action: String(intent.getAction()),
      component: String(intent.getComponent()),
      data: data ? safeUrl(data.toString()) : null
    };
  } catch (_) {
    return { error: 'intent-unavailable' };
  }
}

function firstToken(value) {
  try {
    var s = String(value).trim();
    if (!s) return '';
    return s.split(/\s+/)[0];
  } catch (_) {
    return '';
  }
}

Java.perform(function () {
  try {
    var WebView = Java.use('android.webkit.WebView');
    var loadUrl = WebView.loadUrl.overload('java.lang.String');
    loadUrl.implementation = function (url) {
      emit('webview.loadUrl', { url: safeUrl(url) });
      return loadUrl.call(this, url);
    };
    var addJs = WebView.addJavascriptInterface.overload('java.lang.Object', 'java.lang.String');
    addJs.implementation = function (obj, name) {
      emit('webview.addJavascriptInterface', { name: String(name), className: obj ? String(obj.$className) : null });
      return addJs.call(this, obj, name);
    };
    var postUrl = WebView.postUrl.overload('java.lang.String', '[B');
    postUrl.implementation = function (url, body) {
      emit('webview.postUrl', { url: safeUrl(url), bodyLength: body ? body.length : 0 });
      return postUrl.call(this, url, body);
    };
    var evalJs = WebView.evaluateJavascript.overload('java.lang.String', 'android.webkit.ValueCallback');
    evalJs.implementation = function (script, callback) {
      emit('webview.evaluateJavascript', { scriptLength: script ? String(script).length : 0 });
      return evalJs.call(this, script, callback);
    };
  } catch (e) { emit('hook.error', { hook: 'WebView', error: String(e) }); }

  try {
    var SslErrorHandler = Java.use('android.webkit.SslErrorHandler');
    var proceed = SslErrorHandler.proceed.overload();
    proceed.implementation = function () {
      emit('tls.webviewSslErrorProceed', {});
      return proceed.call(this);
    };
  } catch (_) {}

  try {
    var CookieManager = Java.use('android.webkit.CookieManager');
    var setCookie = CookieManager.setCookie.overload('java.lang.String', 'java.lang.String');
    setCookie.implementation = function (url, value) {
      emit('webview.setCookie', { url: safeUrl(url), valueLength: value ? String(value).length : 0 });
      return setCookie.call(this, url, value);
    };
  } catch (_) {}

  try {
    var URL = Java.use('java.net.URL');
    var openConnection = URL.openConnection.overload();
    openConnection.implementation = function () {
      emit('network.urlConnection', { url: safeUrl(this.toString()) });
      return openConnection.call(this);
    };
  } catch (_) {}

  try {
    var OkHttpBuilder = Java.use('okhttp3.Request$Builder');
    var build = OkHttpBuilder.build.overload();
    build.implementation = function () {
      var request = build.call(this);
      try {
        emit('network.okhttpRequest', { method: String(request.method()), url: safeUrl(request.url().toString()) });
      } catch (_) {}
      return request;
    };
  } catch (_) {}

  try {
    var System = Java.use('java.lang.System');
    var loadLibrary = System.loadLibrary.overload('java.lang.String');
    loadLibrary.implementation = function (name) {
      emit('native.loadLibrary', { name: String(name) });
      return loadLibrary.call(this, name);
    };
  } catch (e) { emit('hook.error', { hook: 'System.loadLibrary', error: String(e) }); }

  try {
    var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
    var dexInit = DexClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader');
    dexInit.implementation = function (dexPath, optDir, libPath, parent) {
      emit('runtime.dexClassLoader', { dexPath: String(dexPath), libraryPath: String(libPath) });
      return dexInit.call(this, dexPath, optDir, libPath, parent);
    };
  } catch (e) { emit('hook.error', { hook: 'DexClassLoader', error: String(e) }); }

  try {
    var InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');
    InMemoryDexClassLoader.$init.overloads.forEach(function (overload) {
      overload.implementation = function () {
        emit('runtime.inMemoryDexClassLoader', { argumentCount: arguments.length });
        return overload.apply(this, arguments);
      };
    });
  } catch (_) {}

  try {
    var Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
    var putString = Editor.putString.overload('java.lang.String', 'java.lang.String');
    putString.implementation = function (key, value) {
      emit('storage.sharedPreferences.putString', { key: String(key), valueLength: value ? String(value).length : 0 });
      return putString.call(this, key, value);
    };
  } catch (_) {}

  try {
    var SQLite = Java.use('android.database.sqlite.SQLiteDatabase');
    var insert = SQLite.insertWithOnConflict.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues', 'int');
    insert.implementation = function (table, nullColumnHack, values, conflict) {
      var keys = [];
      try {
        var it = values.keySet().iterator();
        while (it.hasNext()) keys.push(String(it.next()));
      } catch (_) {}
      emit('storage.sqlite.insert', { table: String(table), keys: keys, conflictAlgorithm: conflict });
      return insert.call(this, table, nullColumnHack, values, conflict);
    };
  } catch (_) {}

  try {
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    var skInit = SecretKeySpec.$init.overload('[B', 'java.lang.String');
    skInit.implementation = function (key, algorithm) {
      emit('crypto.secretKeySpec', { algorithm: String(algorithm), keyLength: key ? key.length : 0 });
      return skInit.call(this, key, algorithm);
    };
  } catch (_) {}

  try {
    var Cipher = Java.use('javax.crypto.Cipher');
    var cipherGet = Cipher.getInstance.overload('java.lang.String');
    cipherGet.implementation = function (transformation) {
      emit('crypto.cipher', { transformation: String(transformation) });
      return cipherGet.call(this, transformation);
    };
  } catch (_) {}

  try {
    var MessageDigest = Java.use('java.security.MessageDigest');
    var digestGet = MessageDigest.getInstance.overload('java.lang.String');
    digestGet.implementation = function (algorithm) {
      emit('crypto.messageDigest', { algorithm: String(algorithm) });
      return digestGet.call(this, algorithm);
    };
  } catch (_) {}

  try {
    var ContextWrapper = Java.use('android.content.ContextWrapper');
    var startActivity = ContextWrapper.startActivity.overload('android.content.Intent');
    startActivity.implementation = function (intent) {
      emit('intent.startActivity', safeIntent(intent));
      return startActivity.call(this, intent);
    };
  } catch (_) {}

  try {
    var Runtime = Java.use('java.lang.Runtime');
    var execString = Runtime.exec.overload('java.lang.String');
    execString.implementation = function (command) {
      emit('runtime.exec', { executable: firstToken(command), commandLength: command ? String(command).length : 0 });
      return execString.call(this, command);
    };
  } catch (_) {}

  try {
    var Debug = Java.use('android.os.Debug');
    var isDebuggerConnected = Debug.isDebuggerConnected.overload();
    isDebuggerConnected.implementation = function () {
      var value = isDebuggerConnected.call(this);
      emit('antiAnalysis.isDebuggerConnected', { result: !!value });
      return value;
    };
  } catch (_) {}

  emit('observer.ready', {});
});
