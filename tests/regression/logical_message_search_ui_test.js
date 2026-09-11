const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname, '../../js/functions.js'), 'utf8');
const handlers = {};
const values = {'#search_mode': 'logical'};
let requests = 0;
let focused = false;
const input = {value: 'error timeout', selectionStart: 6, selectionEnd: 6,
	focus() { focused = true; },
	setSelectionRange(start, end) { this.selectionStart = start; this.selectionEnd = end; }};
const context = {
	$: selector => ({
		val: () => values[selector],
		toggle() { return this; },
		focus() { focused = true; },
		data: () => selector.operator,
		on(event, handler) { handlers[selector + ':' + event] = handler; return this; }
	}),
	document: {getElementById: () => input},
	applyFilter() { requests++; }
};
const start = source.indexOf("\t\t$('#logical_search_controls').toggle");
const end = source.indexOf("\t\t$('#syslog_form').submit", start);
vm.runInNewContext(source.slice(start, end), context);
handlers['.syslogSearchOperator:click'].call({operator: 'AND'});
assert.equal(input.value, 'error AND timeout');
assert.equal(input.selectionStart, 10);
assert.equal(focused, true);
assert.equal(requests, 0);
input.value = 'error timeout';
input.selectionStart = 6;
input.selectionEnd = 13;
handlers['.syslogSearchOperator:click'].call({operator: 'OR'});
assert.equal(input.value, 'error OR ');
handlers['#rfilter:change']();
assert.equal(requests, 0, 'Logical edits must not submit incomplete expressions');
values['#search_mode'] = 'regex';
handlers['#rfilter:change']();
assert.equal(requests, 1, 'Regex change still submits');
// Export sends the active tab and current (possibly unapplied) expression.
context.window = {pageTab: 'alerts'};
context.Pace = {stop() {}};
context.base64_encode = value => Buffer.from(value).toString('base64');
values['#rfilter'] = 'error OR "a&b"';
values['#search_mode'] = 'logical';
const exportStart = source.indexOf('function exportRecords()');
const exportEnd = source.indexOf('/**', exportStart);
vm.runInNewContext(source.slice(exportStart, exportEnd), context);
context.exportRecords();
let url = new URL(context.document.location, 'http://localhost/');
assert.equal(url.searchParams.get('tab'), 'alerts');
assert.equal(url.searchParams.get('search_mode'), 'logical');
assert.equal(url.searchParams.get('rfilter'), values['#rfilter']);
values['#search_mode'] = 'regex';
context.exportRecords();
url = new URL(context.document.location, 'http://localhost/');
assert.equal(Buffer.from(url.searchParams.get('rfilter'), 'base64').toString(), values['#rfilter']);
console.log('logical_message_search_ui_test passed');
