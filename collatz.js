var canvassize = 640;

var canvas;
var ctx;

var paths;       // Liste von Polylinien in Einheitskoordinaten
var minx, maxx, miny, maxy;
var scale;
var offsetx;
var offsety;

var drawindex;
var running = false;
var animationframe;
var pathsperframe = 25;

var colorline;
var colorsingle;

function initialize() {
    canvas = document.getElementById('collatzcanvas');
    canvas.width = canvassize;
    canvas.height = canvassize;
    ctx = canvas.getContext('2d');

    var styles = getComputedStyle(document.documentElement);
    colorline = styles.getPropertyValue('--cell-live').trim();
    colorsingle = styles.getPropertyValue('--ant-color').trim();

    document.getElementById('start').onclick = startbuttonHandler;
    document.getElementById('clear').onclick = clearbuttonHandler;
    document.getElementById('single').oninput = singlehandler;

    clearcanvas();
}

function clearcanvas() {
    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--bg-end').trim();
    ctx.fillRect(0, 0, canvassize, canvassize);
}

// Collatz-Folge von n bis 1
function collatzsequence(n) {
    var seq = [n];
    while (n !== 1) {
        n = (n % 2 === 0) ? n / 2 : 3 * n + 1;
        seq.push(n);
    }
    return seq;
}

// Folge rueckwaerts (von 1 aus) als Linienzug: gerade Vorgaenger drehen
// in die eine, ungerade in die andere Richtung
function buildpath(n, angleeven, angleodd) {
    var seq = collatzsequence(n).reverse();
    var x = 0;
    var y = 0;
    var angle = -Math.PI / 2;
    var points = [{ x: x, y: y }];

    for (var i = 1; i < seq.length; i++) {
        angle += (seq[i] % 2 === 0) ? angleeven : -angleodd;
        x += Math.cos(angle);
        y += Math.sin(angle);
        points.push({ x: x, y: y });
    }
    return points;
}

function buildall(limit, angleeven, angleodd) {
    paths = [];
    minx = Infinity; maxx = -Infinity;
    miny = Infinity; maxy = -Infinity;

    for (var n = 1; n <= limit; n++) {
        var path = buildpath(n, angleeven, angleodd);
        paths.push(path);
        for (var i = 0; i < path.length; i++) {
            if (path[i].x < minx) minx = path[i].x;
            if (path[i].x > maxx) maxx = path[i].x;
            if (path[i].y < miny) miny = path[i].y;
            if (path[i].y > maxy) maxy = path[i].y;
        }
    }

    var margin = 20;
    var w = Math.max(maxx - minx, 1);
    var h = Math.max(maxy - miny, 1);
    scale = Math.min((canvassize - 2 * margin) / w, (canvassize - 2 * margin) / h);
    offsetx = (canvassize - w * scale) / 2 - minx * scale;
    offsety = (canvassize - h * scale) / 2 - miny * scale;
}

function drawpath(path, color, width, alpha) {
    ctx.globalAlpha = alpha;
    ctx.strokeStyle = color;
    ctx.lineWidth = width;
    ctx.lineJoin = 'round';
    ctx.beginPath();
    ctx.moveTo(path[0].x * scale + offsetx, path[0].y * scale + offsety);
    for (var i = 1; i < path.length; i++) {
        ctx.lineTo(path[i].x * scale + offsetx, path[i].y * scale + offsety);
    }
    ctx.stroke();
    ctx.globalAlpha = 1;
}

function readparams() {
    var limit = parseInt(document.getElementById('limit').value, 10);
    if (isNaN(limit) || limit < 10) limit = 10;
    if (limit > 20000) limit = 20000;
    return {
        limit: limit,
        even: document.getElementById('angleeven').value / 100,
        odd: document.getElementById('angleodd').value / 100
    };
}

function startbuttonHandler() {
    stopanimation();
    var p = readparams();
    buildall(p.limit, p.even, p.odd);
    clearcanvas();
    drawindex = 0;
    running = true;
    animate();
}

function animate() {
    for (var i = 0; i < pathsperframe && drawindex < paths.length; i++) {
        drawpath(paths[drawindex], colorline, 1, 0.25);
        drawindex++;
    }
    document.getElementById('info').textContent =
        "Startzahlen: " + drawindex + " / " + paths.length;

    if (running && drawindex < paths.length) {
        animationframe = requestAnimationFrame(animate);
    } else {
        running = false;
        highlightsingle();
    }
}

// Einzelfolge hervorheben (nur wenn das Bild schon gezeichnet wurde)
function singlehandler() {
    var n = parseInt(document.getElementById('single').value, 10);
    var out = document.getElementById('sequence');
    if (isNaN(n) || n < 1) {
        out.textContent = "";
        return;
    }
    if (n > 1000000000) n = 1000000000;
    var seq = collatzsequence(n);
    var max = Math.max.apply(null, seq);
    out.textContent = "Folge fuer " + n + ": " + seq.length + " Zahlen, Maximum " + max +
        (seq.length <= 80 ? " | " + seq.join(" → ") : "");
    if (paths && !running) highlightsingle();
}

function highlightsingle() {
    var n = parseInt(document.getElementById('single').value, 10);
    if (isNaN(n) || n < 1 || !paths) return;
    var p = readparams();
    // Folge ausserhalb der berechneten Startzahlen mit denselben Parametern zeichnen
    var path = buildpath(n, p.even, p.odd);
    drawpath(path, colorsingle, 2, 1);
}

function stopanimation() {
    running = false;
    cancelAnimationFrame(animationframe);
}

function clearbuttonHandler() {
    stopanimation();
    paths = null;
    clearcanvas();
    document.getElementById('info').textContent = "Startzahlen: 0";
}

window.onload = initialize;
