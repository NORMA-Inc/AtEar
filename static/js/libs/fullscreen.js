function requestFullScreen() {
 var element = document.body;
 console.debug(element);
    // Supports most browsers and their versions.
    var requestMethod = element.requestFullScreen || element.webkitRequestFullScreen || element.mozRequestFullScreen || element.msRequestFullScreen;

    if (requestMethod) { // Native full screen.
        requestMethod.call(element);
    } else if (typeof window.ActiveXObject !== "undefined") { // Older IE.
        var wscript = new ActiveXObject("WScript.Shell");
        if (wscript !== null) {
            wscript.SendKeys("{F11}");
        }
    }
 docElm = document.documentElement;
 if (docElm.requestFullscreen) {
     docElm.requestFullscreen();
 }
 else if (docElm.mozRequestFullScreen) {
     docElm.mozRequestFullScreen();
 }
 else if (docElm.webkitRequestFullScreen) {
     docElm.webkitRequestFullScreen(Element.ALLOW_KEYBOARD_INPUT);
 }
}