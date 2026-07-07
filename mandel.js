var canvaswidth = 700;
var canvasheight = 500;

var basecenterre = -0.75;
var basecenterim = 0;
var baserange = 3.5;
var maxiterbase = 150;

var centerre = basecenterre;
var centerim = basecenterim;
var range = baserange;

var zoomhistory = [];

var canvas;
var ctx;

function initialize() {
    canvas = document.getElementById('mandelcanvas');
    canvas.width = canvaswidth;
    canvas.height = canvasheight;
    ctx = canvas.getContext('2d');

    canvas.onclick = canvasclickhandler;
    document.getElementById('zoomout').onclick = zoomouthandler;
    document.getElementById('reset').onclick = resethandler;

    render();
}

function canvasclickhandler(event) {
    var rect = canvas.getBoundingClientRect();
    var px = (event.clientX - rect.left) * (canvaswidth / rect.width);
    var py = (event.clientY - rect.top) * (canvasheight / rect.height);
    var c = pixeltocomplex(px, py);

    zoomhistory.push({ re: centerre, im: centerim, range: range });

    centerre = c.re;
    centerim = c.im;
    range = range * 0.4;

    render();
}

function zoomouthandler() {
    var previous = zoomhistory.pop();
    if (previous) {
        centerre = previous.re;
        centerim = previous.im;
        range = previous.range;
        render();
    }
}

function resethandler() {
    zoomhistory = [];
    centerre = basecenterre;
    centerim = basecenterim;
    range = baserange;
    render();
}

function pixeltocomplex(px, py) {
    var rangere = range;
    var rangeim = range * (canvasheight / canvaswidth);
    var re = centerre + (px / canvaswidth - 0.5) * rangere;
    var im = centerim + (py / canvasheight - 0.5) * rangeim;
    return { re: re, im: im };
}

function render() {
    var rangere = range;
    var rangeim = range * (canvasheight / canvaswidth);
    var minre = centerre - rangere / 2;
    var minim = centerim - rangeim / 2;
    var maxiter = Math.min(1000, Math.round(maxiterbase + 60 * Math.log2(baserange / range + 1)));

    var imagedata = ctx.createImageData(canvaswidth, canvasheight);
    var data = imagedata.data;

    for (var y = 0; y < canvasheight; y++) {
        var ci = minim + (y / canvasheight) * rangeim;
        for (var x = 0; x < canvaswidth; x++) {
            var cr = minre + (x / canvaswidth) * rangere;
            var iter = escapeiterations(cr, ci, maxiter);
            var idx = (y * canvaswidth + x) * 4;
            setpixelcolor(data, idx, iter, maxiter);
        }
    }

    ctx.putImageData(imagedata, 0, 0);
}

function escapeiterations(cr, ci, maxiter) {
    var zr = 0;
    var zi = 0;
    var zr2 = 0;
    var zi2 = 0;
    var iter = 0;

    while (zr2 + zi2 <= 4 && iter < maxiter) {
        zi = 2 * zr * zi + ci;
        zr = zr2 - zi2 + cr;
        zr2 = zr * zr;
        zi2 = zi * zi;
        iter++;
    }

    return iter;
}

function setpixelcolor(data, idx, iter, maxiter) {
    if (iter === maxiter) {
        data[idx] = 13;
        data[idx + 1] = 14;
        data[idx + 2] = 20;
        data[idx + 3] = 255;
        return;
    }

    var t = iter / maxiter;
    var hue = 200 + t * 160;
    var sat = 0.7;
    var light = 0.15 + t * 0.55;
    var rgb = hsltorgb(hue / 360, sat, light);

    data[idx] = rgb[0];
    data[idx + 1] = rgb[1];
    data[idx + 2] = rgb[2];
    data[idx + 3] = 255;
}

function hsltorgb(h, s, l) {
    var r, g, b;

    if (s === 0) {
        r = g = b = l;
    } else {
        var hue2rgb = function (p, q, t) {
            if (t < 0) t += 1;
            if (t > 1) t -= 1;
            if (t < 1 / 6) return p + (q - p) * 6 * t;
            if (t < 1 / 2) return q;
            if (t < 2 / 3) return p + (q - p) * (2 / 3 - t) * 6;
            return p;
        };
        var q = l < 0.5 ? l * (1 + s) : l + s - l * s;
        var p = 2 * l - q;
        r = hue2rgb(p, q, h + 1 / 3);
        g = hue2rgb(p, q, h);
        b = hue2rgb(p, q, h - 1 / 3);
    }

    return [Math.round(r * 255), Math.round(g * 255), Math.round(b * 255)];
}

window.onload = initialize;
