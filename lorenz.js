var canvassize = 640;
var canvas;
var ctx;

var sigma = 10;
var beta = 8 / 3;
var rho = 28;

var dt = 0.005;
var stepsperframe = 4;
var maxtrail = 3000;
var deltas = [0, 0.000001, 0.001, 0.1];

// Zwei Bahnen: a und b
var trailA;
var trailB;
var stateA;
var stateB;

var running = true;
var animationframe;
var stepcount = 0;

var colora;
var colorb;
var colorbg;

function initialize() {
    canvas = document.getElementById('chaoscanvas');
    canvas.width = canvassize;
    canvas.height = canvassize;
    ctx = canvas.getContext('2d');

    var styles = getComputedStyle(document.documentElement);
    colora = styles.getPropertyValue('--cell-live').trim();
    colorb = styles.getPropertyValue('--ant-color').trim();
    colorbg = styles.getPropertyValue('--bg-end').trim();

    document.getElementById('start').onclick = startbuttonHandler;
    document.getElementById('clear').onclick = resetsimulation;
    document.getElementById('rho').oninput = function () {
        rho = parseFloat(this.value);
        document.getElementById('rhovalue').textContent = rho;
    };
    document.getElementById('delta').oninput = function () {
        document.getElementById('deltavalue').textContent = deltas[this.value];
        resetsimulation();
    };

    resetsimulation();
    animate();
}

function currentdelta() {
    return deltas[parseInt(document.getElementById('delta').value, 10)];
}

function resetsimulation() {
    stateA = [1, 1, 1];
    stateB = [1 + currentdelta(), 1, 1];
    trailA = [];
    trailB = [];
    stepcount = 0;
    draw();
}

function derivative(s) {
    return [
        sigma * (s[1] - s[0]),
        s[0] * (rho - s[2]) - s[1],
        s[0] * s[1] - beta * s[2]
    ];
}

function addscaled(s, d, f) {
    return [s[0] + d[0] * f, s[1] + d[1] * f, s[2] + d[2] * f];
}

// Runge-Kutta 4. Ordnung
function rk4(s) {
    var k1 = derivative(s);
    var k2 = derivative(addscaled(s, k1, dt / 2));
    var k3 = derivative(addscaled(s, k2, dt / 2));
    var k4 = derivative(addscaled(s, k3, dt));
    return [
        s[0] + dt / 6 * (k1[0] + 2 * k2[0] + 2 * k3[0] + k4[0]),
        s[1] + dt / 6 * (k1[1] + 2 * k2[1] + 2 * k3[1] + k4[1]),
        s[2] + dt / 6 * (k1[2] + 2 * k2[2] + 2 * k3[2] + k4[2])
    ];
}

function step() {
    stateA = rk4(stateA);
    stateB = rk4(stateB);
    trailA.push(stateA);
    trailB.push(stateB);
    if (trailA.length > maxtrail) {
        trailA.shift();
        trailB.shift();
    }
    stepcount++;
}

// Projektion auf die x-z-Ebene (Schmetterling)
function px(s) {
    return canvassize / 2 + s[0] * (canvassize / 50);
}

function py(s) {
    return canvassize - 30 - s[2] * (canvassize / 60);
}

function drawtrail(trail, color) {
    if (trail.length < 2) return;
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    ctx.lineJoin = 'round';
    ctx.beginPath();
    ctx.moveTo(px(trail[0]), py(trail[0]));
    for (var i = 1; i < trail.length; i++) {
        ctx.lineTo(px(trail[i]), py(trail[i]));
    }
    ctx.stroke();

    var head = trail[trail.length - 1];
    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(px(head), py(head), 4, 0, 2 * Math.PI);
    ctx.fill();
}

function draw() {
    ctx.fillStyle = colorbg;
    ctx.fillRect(0, 0, canvassize, canvassize);
    ctx.globalAlpha = 0.85;
    drawtrail(trailA, colora);
    drawtrail(trailB, colorb);
    ctx.globalAlpha = 1;

    var dist = Math.sqrt(
        Math.pow(stateA[0] - stateB[0], 2) +
        Math.pow(stateA[1] - stateB[1], 2) +
        Math.pow(stateA[2] - stateB[2], 2));
    document.getElementById('info').textContent =
        "Schritte: " + stepcount + " | Abstand der Bahnen: " + dist.toPrecision(3);
}

function animate() {
    if (running) {
        for (var i = 0; i < stepsperframe; i++) {
            step();
        }
        draw();
    }
    animationframe = requestAnimationFrame(animate);
}

function startbuttonHandler() {
    running = !running;
    this.innerHTML = running ? "Pause" : "Weiter";
}

window.onload = initialize;
