/**
 * tty.js
 * Copyright (c) 2012-2013, Christopher Jeffrey (MIT License)
 * Copyright 2014, IBM Corporation
 * Copyright 2014, Lenovo
 */

;(function() {

'use strict';
/**
 * Elements
 */

var document = this.document
  , window = this
  , root
  , body
  , h1
  , open
  , lights;

/**
 * Helpers
 */

var EventEmitter = Terminal.EventEmitter
  , inherits = Terminal.inherits
  , on = Terminal.on
  , off = Terminal.off
  , cancel = Terminal.cancel;

function postRequest(url, data, success) {
	var request = new XMLHttpRequest();
	request.open('POST', url, true);
        request.setRequestHeader('Content-Type', 'application/json');
        request.setRequestHeader('Accept', 'application/json');
	request.onload = function() {
		if (this.status >= 200 && this.status < 400) {
			success(JSON.parse(this.responseText));
		}
	};
	if (data) {
		request.send(JSON.stringify(data));
	} else {
		request.send("");
	}
        request = null;
}
/**
 * Console
 */

function ConsoleWindow(consoleurl, nodename) {
  var self = this;

  if (!(this instanceof ConsoleWindow)) {
    return new ConsoleWindow(consoleurl, nodename);
  }

  EventEmitter.call(this);

  var el
    , grip
    , bar
    , button
    , title;

  el = document.createElement('div');
  el.className = 'window';

  grip = document.createElement('div');
  grip.className = 'grip';

  bar = document.createElement('div');
  bar.className = 'bar';

  button = document.createElement('div');
  button.innerHTML = 'x';
  button.title = 'close';
  button.className = 'tab';

  title = document.createElement('div');
  title.className = 'title';
  title.innerHTML = nodename;

  this.nodename = nodename;
  this.element = el;
  this.grip = grip;
  this.bar = bar;
  this.button = button;
  this.title = title;
  this.consoleurl = consoleurl;

  this.tabs = [];
  this.focused = null;

  this.cols = 100; //Terminal.geometry[0];
  this.rows = 30; //Terminal.geometry[1];

  el.appendChild(grip);
  el.appendChild(bar);
  bar.appendChild(title);
  bar.appendChild(button);
  document.body.appendChild(el);

  //tty.windows.push(this);

  this.createTab();
  this.focus();
  this.bind();

  this.tabs[0].once('open', function() {
    //tty.emit('open window', self);
    self.emit('open');
  });
}

inherits(ConsoleWindow, EventEmitter);

ConsoleWindow.prototype.bind = function() {
  var self = this
    , el = this.element
    , bar = this.bar
    , grip = this.grip
    , button = this.button
    , last = 0;

  on(button, 'click', function(ev) {
    self.destroy();
    return cancel(ev);
  });

  on(grip, 'mousedown', function(ev) {
    self.focus();
    self.resizing(ev);
    return cancel(ev);
  });

  on(el, 'mousedown', function(ev) {
    if (ev.target !== el && ev.target !== bar) return;

    self.focus();

    cancel(ev);

    if (new Date - last < 600) {
      return self.maximize();
    }
    last = new Date;

    self.drag(ev);

    return cancel(ev);
  });
};

ConsoleWindow.prototype.focus = function() {
  // Restack
  var parent = this.element.parentNode;
  if (parent) {
    parent.removeChild(this.element);
    parent.appendChild(this.element);
  }

  // Focus Foreground Tab
  this.focused.focus();

  //tty.emit('focus window', this);
  this.emit('focus');
};

ConsoleWindow.prototype.destroy = function() {
  if (this.destroyed) return;
  this.destroyed = true;

  if (this.minimize) this.minimize();

  //splice(tty.windows, this);
  //if (tty.windows.length) tty.windows[0].focus();

  this.element.parentNode.removeChild(this.element);

  this.each(function(term) {
    term.destroy();
  });

  //tty.emit('close window', this);
  this.emit('close');
};

ConsoleWindow.prototype.drag = function(ev) {
  var self = this
    , el = this.element;

  if (this.minimize) return;

  var drag = {
    left: el.offsetLeft,
    top: el.offsetTop,
    pageX: ev.pageX,
    pageY: ev.pageY
  };

  el.style.opacity = '0.60';
  el.style.cursor = 'move';
  document.documentElement.style.cursor = 'move';

  function move(ev) {
    el.style.left =
      (drag.left + ev.pageX - drag.pageX) + 'px';
    var tmptop = (drag.top + ev.pageY - drag.pageY);
    if (tmptop < 0) {
       tmptop = 0;
    }
    el.style.top = tmptop + 'px';
  }

  function up() {
    el.style.opacity = '';
    el.style.cursor = '';
    document.documentElement.style.cursor = '';

    off(document, 'mousemove', move);
    off(document, 'mouseup', up);

    var ev = {
      left: el.style.left.replace(/\w+/g, ''),
      top: el.style.top.replace(/\w+/g, '')
    };

    //tty.emit('drag window', self, ev);
    self.emit('drag', ev);
  }

  on(document, 'mousemove', move);
  on(document, 'mouseup', up);
};

ConsoleWindow.prototype.resizing = function(ev) {
  var self = this
    , el = this.element
    , term = this.focused;

  if (this.minimize) delete this.minimize;

  var resize = {
    w: el.clientWidth,
    h: el.clientHeight
  };

  el.style.overflow = 'hidden';
  el.style.opacity = '0.70';
  el.style.cursor = 'se-resize';
  document.documentElement.style.cursor = 'se-resize';
  term.element.style.height = '100%';

  function move(ev) {
    var x, y;
    y = el.offsetHeight - term.element.clientHeight;
    x = ev.pageX - el.offsetLeft;
    y = (ev.pageY - el.offsetTop) - y;
    el.style.width = x + 'px';
    el.style.height = y + 'px';
  }

  function up() {
    var x, y;

    x = el.clientWidth / resize.w;
    y = el.clientHeight / resize.h;
    x = (x * term.cols) | 0;
    y = (y * term.rows) | 0;

    self.resize(x, y);

    el.style.width = '';
    el.style.height = '';

    el.style.overflow = '';
    el.style.opacity = '';
    el.style.cursor = '';
    document.documentElement.style.cursor = '';
    term.element.style.height = '';

    off(document, 'mousemove', move);
    off(document, 'mouseup', up);
  }

  on(document, 'mousemove', move);
  on(document, 'mouseup', up);
};

ConsoleWindow.prototype.maximize = function() {
  if (this.minimize) return this.minimize();

  var self = this
    , el = this.element
    , term = this.focused
    , x
    , y;

  var m = {
    cols: term.cols,
    rows: term.rows,
    left: el.offsetLeft,
    top: el.offsetTop,
    root: root.className
  };

  this.minimize = function() {
    delete this.minimize;

    el.style.left = m.left + 'px';
    el.style.top = m.top + 'px';
    el.style.width = '';
    el.style.height = '';
    term.element.style.width = '';
    term.element.style.height = '';
    el.style.boxSizing = '';
    self.grip.style.display = '';
    root.className = m.root;

    self.resize(m.cols, m.rows);

    //tty.emit('minimize window', self);
    self.emit('minimize');
  };

  window.scrollTo(0, 0);

  x = root.clientWidth / term.element.offsetWidth;
  y = root.clientHeight / term.element.offsetHeight;
  x = (x * term.cols) | 0;
  y = (y * term.rows) | 0;

  el.style.left = '0px';
  el.style.top = '0px';
  el.style.width = '100%';
  el.style.height = '100%';
  term.element.style.width = '100%';
  term.element.style.height = '100%';
  el.style.boxSizing = 'border-box';
  this.grip.style.display = 'none';
  root.className = 'maximized';

  this.resize(x, y);

  //tty.emit('maximize window', this);
  this.emit('maximize');
};

ConsoleWindow.prototype.resize = function(cols, rows) {
  this.cols = cols;
  this.rows = rows;

  this.each(function(term) {
    term.resize(cols, rows);
  });

  //tty.emit('resize window', this, cols, rows);
  this.emit('resize', cols, rows);
};

ConsoleWindow.prototype.each = function(func) {
  var i = this.tabs.length;
  while (i--) {
    func(this.tabs[i], i);
  }
};

ConsoleWindow.prototype.createTab = function() {
  return new Tab(this, this.consoleurl);
};

ConsoleWindow.prototype.highlight = function() {
  var self = this;

  this.element.style.borderColor = 'orange';
  setTimeout(function() {
    self.element.style.borderColor = '';
  }, 200);

  this.focus();
};

ConsoleWindow.prototype.focusTab = function(next) {
  var tabs = this.tabs
    , i = indexOf(tabs, this.focused)
    , l = tabs.length;

  if (!next) {
    if (tabs[--i]) return tabs[i].focus();
    if (tabs[--l]) return tabs[l].focus();
  } else {
    if (tabs[++i]) return tabs[i].focus();
    if (tabs[0]) return tabs[0].focus();
  }

  return this.focused && this.focused.focus();
};

ConsoleWindow.prototype.nextTab = function() {
  return this.focusTab(true);
};

ConsoleWindow.prototype.previousTab = function() {
  return this.focusTab(false);
};

/**
 * Tab
 */

function Tab(win, consoleurl) {
  var self = this;

  var cols = win.cols
    , rows = win.rows;

  Terminal.call(this, {
    cols: cols,
    rows: rows
  });

  var button = document.createElement('div');
  button.className = 'tab';
  button.innerHTML = '\u2022';
  //win.bar.appendChild(button);

  on(button, 'click', function(ev) {
    if (ev.ctrlKey || ev.altKey || ev.metaKey || ev.shiftKey) {
      self.destroy();
    } else {
      self.focus();
    }
    return cancel(ev);
  });

  this.id = '';
  this.consoleurl = consoleurl;
  this.clientcount = 0;
  this.connectstate = 'unconnected';
  this.lasterror = ''
  this.window = win;
  this.button = button;
  this.element = null;
  this.process = '';
  this.open();
  this.hookKeys();
  // Now begins the code that will embarass me when I actually know my way
  // around javascript -jbjohnso
  this.sessid = '';
  this.datapending = false;
  this.waitingdata = false;
  this.sentdata = function(data, textStatus, jqXHR) {
    if (this.waitingdata) {
      postRequest(consoleurl,  { session: this.sessid, bytes: this.waitingdata }, this.sentdata);
      this.waitingdata = false;
    } else {
        this.datapending = false;
    }
  }.bind(this);
  this.on('data', function(data) {
    // Send data to console from terminal
    if (this.datapending) {
      if (!this.waitingdata) {
        this.waitingdata = data;
      } else {
        this.waitingdata = this.waitingdata + data;
      }
      return;
    }
    this.datapending = true;
    postRequest(consoleurl,  { session: this.sessid, bytes: data }, this.sentdata);
  }.bind(this));
  this.gotdata = function(data, textStatus, jqXHR) {
    if ("data" in data) {
       this.write(data.data);
    }
    var updatetitle = false;
    var updateinfo = [];
    if ("connectstate" in data) {
        updatetitle = true;
        this.connectstate = data.connectstate;
    }
    if (this.connectstate != "connected") {
        updateinfo.push(this.connectstate);
    } else {
        self.lasterror = '';
    }
    if ("error" in data) {
        updatetitle = true;
        this.lasterror = data.error
    }
    if (this.lasterror != '') {
        updateinfo.push(this.lasterror);
    }
    if ("clientcount" in data) {
        updatetitle = true;
        this.clientcount = data.clientcount;
    }
    if (this.clientcount > 1) {
        updateinfo.push("clients: " + this.clientcount.toString());
    }
    if (updatetitle == true) {
        if (updateinfo.length > 0) {
            this.window.title.innerHTML = this.window.nodename + " [" + updateinfo.join() + "]";
        } else {
            this.window.title.innerHTML = this.window.nodename;
        }
    }
    postRequest(consoleurl,  { session: this.sessid }, this.gotdata);
  }.bind(this);
  this.gotsession = function(data, textStatus, jqXHR) {
    this.sessid = data.session
    postRequest(consoleurl,  { session: this.sessid }, this.gotdata);
  }.bind(this);
  postRequest(consoleurl,  false, this.gotsession);

  win.tabs.push(this);
};

inherits(Tab, Terminal);

Tab.prototype._write = Tab.prototype.write;

Tab.prototype.write = function(data) {
  if (this.window.focused !== this) this.button.style.color = 'red';
  return this._write(data);
};

Tab.prototype._focus = Tab.prototype.focus;

Tab.prototype.focus = function() {
  if (Terminal.focus === this) return;

  var win = this.window;

  // maybe move to Tab.prototype.switch
  if (win.focused !== this) {
    if (win.focused) {
      if (win.focused.element.parentNode) {
        win.focused.element.parentNode.removeChild(win.focused.element);
      }
      win.focused.button.style.fontWeight = '';
    }

    win.element.appendChild(this.element);
    win.focused = this;

    //win.title.innerHTML = this.process;
    this.button.style.fontWeight = 'bold';
    this.button.style.color = '';
  }

  this._focus();

  win.focus();

  //tty.emit('focus tab', this);
  this.emit('focus');
};

Tab.prototype._resize = Tab.prototype.resize;

Tab.prototype.resize = function(cols, rows) {
  //this.socket.emit('resize', this.id, cols, rows);
  this._resize(cols, rows);
  //tty.emit('resize tab', this, cols, rows);
  this.emit('resize', cols, rows);
};

Tab.prototype.__destroy = Tab.prototype.destroy;

Tab.prototype._destroy = function() {
  if (this.destroyed) return;
  this.destroyed = true;

  var win = this.window;

  this.button.parentNode.removeChild(this.button);
  if (this.element.parentNode) {
    this.element.parentNode.removeChild(this.element);
  }

  if (tty.terms[this.id]) delete tty.terms[this.id];
  splice(win.tabs, this);

  if (win.focused === this) {
    win.previousTab();
  }

  if (!win.tabs.length) {
    win.destroy();
  }

  this.__destroy();
};

Tab.prototype.destroy = function() {
  if (this.destroyed) return;
  //TODO: politely let server know of client closure
  this._destroy();
  //tty.emit('close tab', this);
  this.emit('close');
};

Tab.prototype.hookKeys = function() {
  var self = this;

  // Alt-[jk] to quickly swap between windows.
  this.on('key', function(key, ev) {
    if (Terminal.focusKeys === false) {
      return;
    }

    var offset
      , i;

    if (key === '\x1bj') {
      offset = -1;
    } else if (key === '\x1bk') {
      offset = +1;
    } else {
      return;
    }

    i = indexOf(tty.windows, this.window) + offset;

    this._ignoreNext();

    if (tty.windows[i]) return tty.windows[i].highlight();

    if (offset > 0) {
      if (tty.windows[0]) return tty.windows[0].highlight();
    } else {
      i = tty.windows.length - 1;
      if (tty.windows[i]) return tty.windows[i].highlight();
    }

    return this.window.highlight();
  });

  this.on('request paste', function(key) {
    this.socket.emit('request paste', function(err, text) {
      if (err) return;
      self.send(text);
    });
  });

  this.on('request create', function() {
    this.window.createTab();
  });

  this.on('request term', function(key) {
    if (this.window.tabs[key]) {
      this.window.tabs[key].focus();
    }
  });

  this.on('request term next', function(key) {
    this.window.nextTab();
  });

  this.on('request term previous', function(key) {
    this.window.previousTab();
  });
};

Tab.prototype._ignoreNext = function() {
  // Don't send the next key.
  var handler = this.handler;
  this.handler = function() {
    this.handler = handler;
  };
  var showCursor = this.showCursor;
  this.showCursor = function() {
    this.showCursor = showCursor;
  };
};

/**
 * Program-specific Features
 */

Tab.prototype._bindMouse = Tab.prototype.bindMouse;

Tab.prototype.bindMouse = function() {
  if (!Terminal.programFeatures) return this._bindMouse();

  var self = this;

  var wheelEvent = 'onmousewheel' in window
    ? 'mousewheel'
    : 'DOMMouseScroll';

  on(self.element, wheelEvent, function(ev) {
    if (self.mouseEvents) return;

    if ((ev.type === 'mousewheel' && ev.wheelDeltaY > 0)
        || (ev.type === 'DOMMouseScroll' && ev.detail < 0)) {
      // page up
      self.keyDown({keyCode: 33});
    } else {
      // page down
      self.keyDown({keyCode: 34});
    }

    return cancel(ev);
  });

  return this._bindMouse();
};

/**
 * Helpers
 */

function indexOf(obj, el) {
  var i = obj.length;
  while (i--) {
    if (obj[i] === el) return i;
  }
  return -1;
}

function splice(obj, el) {
  var i = indexOf(obj, el);
  if (~i) obj.splice(i, 1);
}

function sanitize(text) {
  if (!text) return '';
  return (text + '').replace(/[&<>]/g, '')
}

this.ConsoleWindow = ConsoleWindow;

}).call(function() {
    return this;
}());
