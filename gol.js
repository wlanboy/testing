var rows = 60;
var cols = 60;

var gameisrunning = false;

var grid = new Array(rows);
var nextGrid = new Array(rows);

var timer;
var reproductionTime = 100;

function initboard() {
    for (var i = 0; i < rows; i++) {
        grid[i] = new Array(cols);
        nextGrid[i] = new Array(cols);
    }
}

function resetboard() {
    for (var i = 0; i < rows; i++) {
        for (var j = 0; j < cols; j++) {
            grid[i][j] = 0;
            nextGrid[i][j] = 0;
        }
    }
}

function copyAndResetGrid() {
    for (var i = 0; i < rows; i++) {
        for (var j = 0; j < cols; j++) {
            grid[i][j] = nextGrid[i][j];
            nextGrid[i][j] = 0;
        }
    }
}

function initialize() {
    createboard();
    initboard();
    resetboard();
    initbuttons();
}

function createboard() {
    var boardcontainer = document.getElementById('boardcontainer');
    var board = document.createElement("div");
    board.className = "board";
    board.style.gridTemplateColumns = "repeat(" + cols + ", 10px)";

    for (var i = 0; i < rows; i++) {
        for (var j = 0; j < cols; j++) {
            var cell = document.createElement("div");
            cell.setAttribute("id", i + "_" + j);
            cell.setAttribute("class", "cell dead");
            cell.onclick = boardcellhandler;
            board.appendChild(cell);
        }
    }
    boardcontainer.appendChild(board);
}

function boardcellhandler() {
    var rowcol = this.id.split("_");
    var row = rowcol[0];
    var col = rowcol[1];

    var classes = this.getAttribute("class");
    if (classes.indexOf("live") > -1) {
        this.setAttribute("class", "cell dead");
        grid[row][col] = 0;
    } else {
        this.setAttribute("class", "cell live");
        grid[row][col] = 1;
    }
}

function updateView() {
    for (var i = 0; i < rows; i++) {
        for (var j = 0; j < cols; j++) {
            var cell = document.getElementById(i + "_" + j);
            if (grid[i][j] == 0) {
                cell.setAttribute("class", "cell dead");
            } else {
                cell.setAttribute("class", "cell live");
            }
        }
    }
}

function initbuttons() {
    var startbutton = document.getElementById('start');
    startbutton.onclick = startbuttonHandler;
    var clearbutton = document.getElementById('clear');
    clearbutton.onclick = clearbuttonHandler;
    var fillbutton = document.getElementById("fill");
    fillbutton.onclick = fillbuttonHandler;
}

function fillbuttonHandler() {
    if (gameisrunning) return;
    clearbuttonHandler();
    for (var i = 0; i < rows; i++) {
        for (var j = 0; j < cols; j++) {
            var isLive = Math.round(Math.random());
            if (isLive == 1) {
                var cell = document.getElementById(i + "_" + j);
                cell.setAttribute("class", "cell live");
                grid[i][j] = 1;
            }
        }
    }
}

function clearbuttonHandler() {
    gameisrunning = false;
    var startbutton = document.getElementById('start');
    startbutton.innerHTML = "Start";
    clearTimeout(timer);

    var cellsList = document.getElementsByClassName("live");

    var cells = [];
    for (var i = 0; i < cellsList.length; i++) {
        cells.push(cellsList[i]);
    }

    for (var i = 0; i < cells.length; i++) {
        cells[i].setAttribute("class", "cell dead");
    }
    resetboard();
}

function startbuttonHandler() {
    if (gameisrunning) {
        gameisrunning = false;
        this.innerHTML = "Continue";
        clearTimeout(timer);
    } else {
        gameisrunning = true;
        this.innerHTML = "Pause";
        play();
    }
}

function play() {
    computeNextGen();

    if (gameisrunning) {
        timer = setTimeout(play, reproductionTime);
    }
}

function computeNextGen() {
    for (var i = 0; i < rows; i++) {
        for (var j = 0; j < cols; j++) {
            applyRules(i, j);
        }
    }
    copyAndResetGrid();
    updateView();
}

function applyRules(row, col) {
    var numNeighbors = countNeighbors(row, col);
    if (grid[row][col] == 1) {
        if (numNeighbors < 2) {
            nextGrid[row][col] = 0;
        } else if (numNeighbors == 2 || numNeighbors == 3) {
            nextGrid[row][col] = 1;
        } else if (numNeighbors > 3) {
            nextGrid[row][col] = 0;
        }
    } else if (grid[row][col] == 0) {
        if (numNeighbors == 3) {
            nextGrid[row][col] = 1;
        }
    }
}

function countNeighbors(row, col) {
    var count = 0;
    if (row - 1 >= 0) {
        if (grid[row - 1][col] == 1) count++;
    }
    if (row - 1 >= 0 && col - 1 >= 0) {
        if (grid[row - 1][col - 1] == 1) count++;
    }
    if (row - 1 >= 0 && col + 1 < cols) {
        if (grid[row - 1][col + 1] == 1) count++;
    }
    if (col - 1 >= 0) {
        if (grid[row][col - 1] == 1) count++;
    }
    if (col + 1 < cols) {
        if (grid[row][col + 1] == 1) count++;
    }
    if (row + 1 < rows) {
        if (grid[row + 1][col] == 1) count++;
    }
    if (row + 1 < rows && col - 1 >= 0) {
        if (grid[row + 1][col - 1] == 1) count++;
    }
    if (row + 1 < rows && col + 1 < cols) {
        if (grid[row + 1][col + 1] == 1) count++;
    }
    return count;
}

window.onload = initialize;
