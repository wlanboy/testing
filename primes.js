var size = 101;
var cellsize = 6;
var total = size * size;

var canvas;
var ctx;

// Zustand pro Zahl: 0 = unbekannt, 1 = Primzahl, 2 = zusammengesetzt (gestrichen)
var state;
// Position (Zeile/Spalte) jeder Zahl in der Spirale
var posrow;
var poscol;
// Zelle -> Zahl
var cellnumber;

var currentprime;
var sievedone;
var running = false;
var animationframe;
var framecounter = 0;
var framesperstep = 6;

var colorunknown;
var colorprime;
var colorcomposite;
var colorcurrent;

function initialize() {
    canvas = document.getElementById('primecanvas');
    canvas.width = size * cellsize;
    canvas.height = size * cellsize;
    ctx = canvas.getContext('2d');

    readcolors();
    buildspiral();
    resetsieve();
    initbuttons();
    canvas.onmousemove = mousehandler;
    canvas.onmouseleave = function () { setinfo("Faehre mit der Maus ueber eine Zelle"); };
    drawall();
}

function readcolors() {
    var styles = getComputedStyle(document.documentElement);
    colorunknown = styles.getPropertyValue('--cell-border').trim();
    colorprime = styles.getPropertyValue('--cell-live').trim();
    colorcomposite = styles.getPropertyValue('--cell-dead').trim();
    colorcurrent = styles.getPropertyValue('--ant-color').trim();
}

// Ulam-Spirale: 1 in der Mitte, dann rechts, hoch, links, runter ...
function buildspiral() {
    posrow = new Array(total + 1);
    poscol = new Array(total + 1);
    cellnumber = new Array(size * size);

    var row = Math.floor(size / 2);
    var col = Math.floor(size / 2);
    var dx = 1;
    var dy = 0;
    var seglen = 1;
    var segpos = 0;
    var turns = 0;

    for (var n = 1; n <= total; n++) {
        posrow[n] = row;
        poscol[n] = col;
        cellnumber[row * size + col] = n;

        col += dx;
        row += dy;
        segpos++;
        if (segpos === seglen) {
            segpos = 0;
            var tmp = dx;
            dx = dy;
            dy = -tmp;
            turns++;
            if (turns % 2 === 0) seglen++;
        }
    }
}

function resetsieve() {
    state = new Array(total + 1);
    for (var n = 0; n <= total; n++) {
        state[n] = 0;
    }
    state[1] = 2; // 1 ist keine Primzahl
    currentprime = 2;
    sievedone = false;
}

function drawnumber(n) {
    var color = colorunknown;
    if (state[n] === 1) color = colorprime;
    else if (state[n] === 2) color = colorcomposite;
    ctx.fillStyle = color;
    ctx.fillRect(poscol[n] * cellsize, posrow[n] * cellsize, cellsize, cellsize);
}

function drawall() {
    for (var n = 1; n <= total; n++) {
        drawnumber(n);
    }
    updateinfo();
}

// Ein Schritt des Siebs: naechste Primzahl p finden, Vielfache ab p*p streichen
function sievestep() {
    if (sievedone) return;

    while (currentprime <= total && state[currentprime] !== 0) {
        currentprime++;
    }
    if (currentprime > total) {
        sievedone = true;
        return;
    }

    var p = currentprime;
    state[p] = 1;
    drawnumber(p);
    for (var m = p * p; m <= total; m += p) {
        if (state[m] === 0) {
            state[m] = 2;
            drawnumber(m);
        }
    }
    currentprime++;

    // Nach sqrt(total) sind alle uebrigen Zahlen Primzahlen
    if (p * p > total) {
        finishsieve();
    }
}

function finishsieve() {
    for (var n = 2; n <= total; n++) {
        if (state[n] === 0) {
            state[n] = 1;
            drawnumber(n);
        }
    }
    sievedone = true;
}

function updateinfo() {
    var count = 0;
    for (var n = 2; n <= total; n++) {
        if (state[n] === 1) count++;
    }
    if (sievedone) {
        setinfo("Fertig: " + count + " Primzahlen bis " + total);
    } else {
        setinfo("Aktuelle Primzahl: " + (currentprime - 1) + " | bisher gefunden: " + count);
    }
}

function setinfo(text) {
    document.getElementById('info').textContent = text;
}

function mousehandler(event) {
    var rect = canvas.getBoundingClientRect();
    var scale = canvas.width / rect.width;
    var col = Math.floor((event.clientX - rect.left) * scale / cellsize);
    var row = Math.floor((event.clientY - rect.top) * scale / cellsize);
    var n = cellnumber[row * size + col];
    if (!n) return;

    var text = String(n);
    if (state[n] === 1) text += " ist eine Primzahl";
    else if (state[n] === 2) text += n === 1 ? " ist keine Primzahl" : " ist zusammengesetzt";
    else text += " ist noch nicht entschieden";
    setinfo(text);
}

function initbuttons() {
    document.getElementById('start').onclick = startbuttonHandler;
    document.getElementById('step').onclick = stepbuttonHandler;
    document.getElementById('all').onclick = allbuttonHandler;
    document.getElementById('clear').onclick = clearbuttonHandler;
}

function startbuttonHandler() {
    if (sievedone) return;
    if (running) {
        running = false;
        this.innerHTML = "Weiter";
        cancelAnimationFrame(animationframe);
    } else {
        running = true;
        this.innerHTML = "Pause";
        animate();
    }
}

function stepbuttonHandler() {
    if (running) return;
    sievestep();
    updateinfo();
}

function allbuttonHandler() {
    stopanimation();
    finishsievefully();
}

function finishsievefully() {
    while (!sievedone) {
        sievestep();
    }
    updateinfo();
}

function clearbuttonHandler() {
    stopanimation();
    resetsieve();
    drawall();
}

function stopanimation() {
    running = false;
    cancelAnimationFrame(animationframe);
    document.getElementById('start').innerHTML = "Sieb starten";
}

function animate() {
    framecounter++;
    if (framecounter >= framesperstep) {
        framecounter = 0;
        sievestep();
        updateinfo();
    }
    if (sievedone) {
        stopanimation();
        return;
    }
    if (running) {
        animationframe = requestAnimationFrame(animate);
    }
}

window.onload = initialize;
