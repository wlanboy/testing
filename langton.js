var cols = 120;
var rows = 120;
var cellsize = 5;

var canvas;
var ctx;

var grid;

var antrow;
var antcol;
var antdir;

var dirs = [
    { dx: 0, dy: -1 },
    { dx: 1, dy: 0 },
    { dx: 0, dy: 1 },
    { dx: -1, dy: 0 }
];

var running = false;
var animationframe;
var stepsperframe = 20;
var stepcount = 0;

var colorwhite;
var colorblack;
var colorant;

function initialize() {
    canvas = document.getElementById('langtoncanvas');
    canvas.width = cols * cellsize;
    canvas.height = rows * cellsize;
    ctx = canvas.getContext('2d');

    readcolors();
    initboard();
    resetboard();
    initbuttons();
    drawfullgrid();
}

function readcolors() {
    var styles = getComputedStyle(document.documentElement);
    colorwhite = styles.getPropertyValue('--cell-dead').trim();
    colorblack = styles.getPropertyValue('--cell-live').trim();
    colorant = styles.getPropertyValue('--ant-color').trim();
}

function initboard() {
    grid = new Array(rows);
    for (var i = 0; i < rows; i++) {
        grid[i] = new Array(cols);
    }
}

function resetboard() {
    for (var i = 0; i < rows; i++) {
        for (var j = 0; j < cols; j++) {
            grid[i][j] = 0;
        }
    }
    antrow = Math.floor(rows / 2);
    antcol = Math.floor(cols / 2);
    antdir = 0;
    stepcount = 0;
    updatestepcounter();
}

function drawcell(row, col) {
    ctx.fillStyle = grid[row][col] === 1 ? colorblack : colorwhite;
    ctx.fillRect(col * cellsize, row * cellsize, cellsize, cellsize);
}

function drawfullgrid() {
    for (var i = 0; i < rows; i++) {
        for (var j = 0; j < cols; j++) {
            drawcell(i, j);
        }
    }
    drawant();
}

function drawant() {
    ctx.fillStyle = colorant;
    ctx.fillRect(antcol * cellsize, antrow * cellsize, cellsize, cellsize);
}

function singlestep() {
    var row = antrow;
    var col = antcol;

    if (grid[row][col] === 0) {
        antdir = (antdir + 1) % 4;
        grid[row][col] = 1;
    } else {
        antdir = (antdir + 3) % 4;
        grid[row][col] = 0;
    }

    drawcell(row, col);

    antrow = (antrow + dirs[antdir].dy + rows) % rows;
    antcol = (antcol + dirs[antdir].dx + cols) % cols;
    stepcount++;
}

function updatestepcounter() {
    document.getElementById('stepcounter').innerHTML = "Schritte: " + stepcount;
}

function initbuttons() {
    var startbutton = document.getElementById('start');
    startbutton.onclick = startbuttonHandler;
    var stepbutton = document.getElementById('step');
    stepbutton.onclick = stepbuttonHandler;
    var clearbutton = document.getElementById('clear');
    clearbutton.onclick = clearbuttonHandler;
}

function startbuttonHandler() {
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
    singlestep();
    drawant();
    updatestepcounter();
}

function clearbuttonHandler() {
    running = false;
    cancelAnimationFrame(animationframe);
    document.getElementById('start').innerHTML = "Start";
    resetboard();
    drawfullgrid();
}

function animate() {
    for (var i = 0; i < stepsperframe; i++) {
        singlestep();
    }
    drawant();
    updatestepcounter();

    if (running) {
        animationframe = requestAnimationFrame(animate);
    }
}

window.onload = initialize;
