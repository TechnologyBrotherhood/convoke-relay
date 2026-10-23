// A pairing link opened in a browser (e.g. scanned with the system Camera): hand it to the
// Convoke app. Nothing here pairs or connects anywhere; the page only builds a link.
;(function () {
  var hash = location.hash
  if (hash.indexOf('#pair=') !== 0) return
  var link = location.href
  // The code is secret and single-use: keep it out of the address bar and history.
  history.replaceState(null, '', location.pathname)
  var open = document.getElementById('open')
  open.href = 'convoke://pair?link=' + encodeURIComponent(link)
  open.hidden = false
  document.getElementById('what').textContent = 'This is a pairing link for Convoke on your Mac. Open it in the Convoke app on this iPhone; the app asks you to confirm.'
  // On an iPhone or iPad, go straight to the app (Safari asks once); the button stays
  // for when that's dismissed or the app isn't installed. (iPadOS reports a Mac, with touch.)
  var ios = /iPhone|iPad|iPod/.test(navigator.userAgent) || (/Macintosh/.test(navigator.userAgent) && navigator.maxTouchPoints > 1)
  if (ios) location.href = open.href
})()
