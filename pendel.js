var canvassize = 640;
var canvas;
var ctx;

var g = 9.81;
var l1 = 1;
var l2 = 1;
var m1 = 1;
var m2 = 1;

var dt = 0.002;
var stepsperframe = 8;
var maxtrail = 600;
var epsilon = 0.001;
var scale = canvassize / 4.6;

// Zwei Pendel: Zustand [theta1, omega1, theta2, omega2]
var stateA;
var stateB;
var trailA;
var trailB;

var running = true;
var animationframe;
var time = 0;

var colora;
var colorb;
var colorbg;
var colorrod;

function initialize() {
    canvas = document.getElementById('chaoscanvas');
    canvas.width = canvassize;
    canvas.height = canvassize;
    ctx = canvas.getContext('2d');

    var styles = getComputedStyle(document.documentElement);
    colora = styles.getPropertyValue('--cell-live').trim();
    colorb = styles.getPropertyValue('--ant-color').trim();
    colorbg = styles.getPropertyValue('--bg-end').trim();
    colorrod = styles.getPropertyValue('--text-muted').trim();

    document.getElementById('start').onclick = startbuttonHandler;
    document.getElementById('clear').onclick = resetsimulation;
    document.getElementById('a1').oninput = anglehandler;
    document.getElementById('a2').oninput = anglehandler;

    resetsimulation();
    animate();
}

function anglehandler() {
    document.getElementById('a1value').textContent = document.getElementById('a1').value;
    document.getElementById('a2value').textContent = document.getElementById('a2').value;
    resetsimulation();
}

function resetsimulation() {
    var a1 = document.getElementById('a1').value * Math.PI / 180;
    var a2 = document.getElementById('a2').value * Math.PI / 180;
    stateA = [a1, 0, a2, 0];
    stateB = [a1 + epsilon, 0, a2, 0];
    trailA = [];
    trailB = [];
    time = 0;
    draw();
}

function derivative(s) {
    var t1 = s[0];
    var w1 = s[1];
    var t2 = s[2];
    var w2 = s[3];
    var d = t1 - t2;
    var den = 2 * m1 + m2 - m2 * Math.cos(2 * d);

    var a1 = (-g * (2 * m1 + m2) * Math.sin(t1)
        - m2 * g * Math.sin(t1 - 2 * t2)
        - 2 * Math.sin(d) * m2 * (w2 * w2 * l2 + w1 * w1 * l1 * Math.cos(d)))
        / (l1 * den);

    var a2 = (2 * Math.sin(d) * (w1 * w1 * l1 * (m1 + m2)
        + g * (m1 + m2) * Math.cos(t1)
        + w2 * w2 * l2 * m2 * Math.cos(d)))
        / (l2 * den);

    return [w1, a1, w2, a2];
}

function addscaled(s, d, f) {
    return [s[0] + d[0] * f, s[1] + d[1] * f, s[2] + d[2] * f, s[3] + d[3] * f];
}

// Runge-Kutta 4. Ordnung
function rk4(s) {
    var k1 = derivative(s);
    var k2 = derivative(addscaled(s, k1, dt / 2));
    var k3 = derivative(addscaled(s, k2, dt / 2));
    var k4 = derivative(addscaled(s, k3, dt));
    var out = [];
    for (var i = 0; i < 4; i++) {
        out.push(s[i] + dt / 6 * (k1[i] + 2 * k2[i] + 2 * k3[i] + k4[i]));
    }
    return out;
}

// Positionen von Gelenk und Endmasse
function positions(s) {
    var x1 = l1 * Math.sin(s[0]);
    var y1 = l1 * Math.cos(s[0]);
    var x2 = x1 + l2 * Math.sin(s[2]);
    var y2 = y1 + l2 * Math.cos(s[2]);
    return { x1: x1, y1: y1, x2: x2, y2: y2 };
}

function tocanvasx(x) {
    return canvassize / 2 + x * scale;
}

function tocanvasy(y) {
    return canvassize / 2 + y * scale;
}

function step() {
    stateA = rk4(stateA);
    stateB = rk4(stateB);
    time += dt;
}

function recordtrail() {
    trailA.push(positions(stateA));
    trailB.push(positions(stateB));
    if (trailA.length > maxtrail) {
        trailA.shift();
        trailB.shift();
    }
}

function drawtrail(trail, color) {
    if (trail.length < 2) return;
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    ctx.globalAlpha = 0.6;
    ctx.beginPath();
    ctx.moveTo(tocanvasx(trail[0].x2), tocanvasy(trail[0].y2));
    for (var i = 1; i < trail.length; i++) {
        ctx.lineTo(tocanvasx(trail[i].x2), tocanvasy(trail[i].y2));
    }
    ctx.stroke();
    ctx.globalAlpha = 1;
}

function drawpendulum(s, color) {
    var p = positions(s);
    ctx.strokeStyle = colorrod;
    ctx.lineWidth = 2;
    ctx.globalAlpha = 0.7;
    ctx.beginPath();
    ctx.moveTo(tocanvasx(0), tocanvasy(0));
    ctx.lineTo(tocanvasx(p.x1), tocanvasy(p.y1));
    ctx.lineTo(tocanvasx(p.x2), tocanvasy(p.y2));
    ctx.stroke();
    ctx.globalAlpha = 1;

    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(tocanvasx(p.x1), tocanvasy(p.y1), 6, 0, 2 * Math.PI);
    ctx.fill();
    ctx.beginPath();
    ctx.arc(tocanvasx(p.x2), tocanvasy(p.y2), 8, 0, 2 * Math.PI);
    ctx.fill();
}

function draw() {
    ctx.fillStyle = colorbg;
    ctx.fillRect(0, 0, canvassize, canvassize);
    drawtrail(trailA, colora);
    drawtrail(trailB, colorb);
    drawpendulum(stateA, colora);
    drawpendulum(stateB, colorb);

    var pa = positions(stateA);
    var pb = positions(stateB);
    var dist = Math.sqrt(Math.pow(pa.x2 - pb.x2, 2) + Math.pow(pa.y2 - pb.y2, 2));
    document.getElementById('info').textContent =
        "Zeit: " + time.toFixed(1) + " s | Abstand der Endmassen: " + dist.toFixed(3);
}

function animate() {
    if (running) {
        for (var i = 0; i < stepsperframe; i++) {
            step();
        }
        recordtrail();
        draw();
    }
    animationframe = requestAnimationFrame(animate);
}

function startbuttonHandler() {
    running = !running;
    this.innerHTML = running ? "Pause" : "Weiter";
}

window.onload = initialize;
