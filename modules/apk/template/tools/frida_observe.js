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
  } catch (e) { emit('hook.error', { hook: 'WebView', error: String(e) }); }

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
    var ContextWrapper = Java.use('android.content.ContextWrapper');
    var startActivity = ContextWrapper.startActivity.overload('android.content.Intent');
    startActivity.implementation = function (intent) {
      emit('intent.startActivity', safeIntent(intent));
      return startActivity.call(this, intent);
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
