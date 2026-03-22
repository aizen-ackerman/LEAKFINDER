/**
 * Universe star field animation — canvas-based moving stars
 */
document.addEventListener('DOMContentLoaded', function() {
(function() {
    // Create canvas and insert it before .stars (or at body start)
    var canvas = document.createElement('canvas');
    canvas.id = 'universe-canvas';
    document.body.insertBefore(canvas, document.body.firstChild);

    var ctx = canvas.getContext('2d');

    // Star config
    var STAR_COUNT = 280;
    var stars = [];

    function rand(min, max) { return Math.random() * (max - min) + min; }

    function Star() {
        this.reset();
    }

    Star.prototype.reset = function(randomY) {
        this.x     = rand(0, canvas.width);
        this.y     = randomY ? rand(0, canvas.height) : rand(-canvas.height, canvas.height);
        this.r     = rand(0.3, 2.2);          // radius
        this.alpha = rand(0.15, 1.0);          // base brightness
        this.speed = rand(0.06, 0.35);         // drift speed (downward parallax)
        this.drift = rand(-0.08, 0.08);        // horizontal drift
        this.twinkleSpeed = rand(0.005, 0.025);// twinkle frequency
        this.twinkleDir   = Math.random() > 0.5 ? 1 : -1;
        // Colour: mostly white/blue-white, occasional warm tone
        var hue  = Math.random() > 0.85 ? rand(35, 55) : rand(200, 240);
        var sat  = Math.random() > 0.7  ? rand(40, 70) : 0;
        this.color = sat > 0
            ? 'hsl(' + hue + ',' + sat + '%,95%)'
            : '#ffffff';
    };

    function initStars() {
        stars = [];
        for (var i = 0; i < STAR_COUNT; i++) {
            var s = new Star();
            s.reset(true); // spread across full screen at start
            stars.push(s);
        }
    }

    function resize() {
        canvas.width  = window.innerWidth;
        canvas.height = window.innerHeight;
        initStars();
    }

    function draw() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        for (var i = 0; i < stars.length; i++) {
            var s = stars[i];

            // Twinkle
            s.alpha += s.twinkleSpeed * s.twinkleDir;
            if (s.alpha >= 1.0) { s.alpha = 1.0; s.twinkleDir = -1; }
            if (s.alpha <= 0.1) { s.alpha = 0.1; s.twinkleDir =  1; }

            // Move
            s.y += s.speed;
            s.x += s.drift;

            // Wrap around screen
            if (s.y > canvas.height + 5) {
                s.reset(false);
                s.y = -5;
                s.x = rand(0, canvas.width);
            }
            if (s.x < -5)               s.x = canvas.width  + 5;
            if (s.x > canvas.width + 5) s.x = -5;

            // Draw star (larger stars get a soft glow halo)
            ctx.save();
            ctx.globalAlpha = s.alpha;

            if (s.r > 1.4) {
                // Glow
                var grad = ctx.createRadialGradient(s.x, s.y, 0, s.x, s.y, s.r * 4);
                grad.addColorStop(0,   s.color);
                grad.addColorStop(0.4, s.color.replace(')', ', 0.3)').replace('hsl', 'hsla').replace('#ffffff', 'rgba(255,255,255,0.3)'));
                grad.addColorStop(1,   'transparent');
                ctx.fillStyle = grad;
                ctx.beginPath();
                ctx.arc(s.x, s.y, s.r * 4, 0, Math.PI * 2);
                ctx.fill();
            }

            // Core dot
            ctx.fillStyle = s.color;
            ctx.beginPath();
            ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2);
            ctx.fill();

            ctx.restore();
        }

        // Occasional shooting star (1% chance per frame)
        if (Math.random() < 0.004) shootingStar();

        requestAnimationFrame(draw);
    }

    // Shooting stars
    var shoots = [];
    function shootingStar() {
        shoots.push({
            x: rand(0, canvas.width),
            y: rand(0, canvas.height * 0.4),
            len: rand(80, 200),
            angle: rand(20, 60) * Math.PI / 180,
            speed: rand(12, 22),
            alpha: 1.0,
            decay: rand(0.015, 0.04)
        });
    }
    function drawShoots() {
        for (var i = shoots.length - 1; i >= 0; i--) {
            var sh = shoots[i];
            ctx.save();
            ctx.globalAlpha = sh.alpha;
            ctx.strokeStyle = '#ffffff';
            ctx.lineWidth   = 1.5;
            ctx.shadowColor = '#aefff0';
            ctx.shadowBlur  = 6;
            ctx.beginPath();
            ctx.moveTo(sh.x, sh.y);
            ctx.lineTo(sh.x - Math.cos(sh.angle) * sh.len,
                       sh.y - Math.sin(sh.angle) * sh.len);
            ctx.stroke();
            ctx.restore();
            sh.x += Math.cos(sh.angle) * sh.speed;
            sh.y += Math.sin(sh.angle) * sh.speed;
            sh.alpha -= sh.decay;
            if (sh.alpha <= 0) shoots.splice(i, 1);
        }
    }

    // Patch draw to include shooting stars
    var _draw = draw;
    draw = function() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        for (var i = 0; i < stars.length; i++) {
            var s = stars[i];
            s.alpha += s.twinkleSpeed * s.twinkleDir;
            if (s.alpha >= 1.0) { s.alpha = 1.0; s.twinkleDir = -1; }
            if (s.alpha <= 0.1) { s.alpha = 0.1; s.twinkleDir =  1; }
            s.y += s.speed; s.x += s.drift;
            if (s.y > canvas.height + 5) { s.reset(false); s.y = -5; s.x = rand(0, canvas.width); }
            if (s.x < -5)               s.x = canvas.width  + 5;
            if (s.x > canvas.width + 5) s.x = -5;
            ctx.save();
            ctx.globalAlpha = s.alpha;
            if (s.r > 1.4) {
                var g = ctx.createRadialGradient(s.x, s.y, 0, s.x, s.y, s.r * 5);
                g.addColorStop(0,   'rgba(255,255,255,0.8)');
                g.addColorStop(0.5, 'rgba(200,220,255,0.2)');
                g.addColorStop(1,   'transparent');
                ctx.fillStyle = g;
                ctx.beginPath();
                ctx.arc(s.x, s.y, s.r * 5, 0, Math.PI * 2);
                ctx.fill();
            }
            ctx.fillStyle = s.color;
            ctx.beginPath();
            ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2);
            ctx.fill();
            ctx.restore();
        }
        if (Math.random() < 0.004) shootingStar();
        drawShoots();
        requestAnimationFrame(draw);
    };

    window.addEventListener('resize', resize);
    resize();
    requestAnimationFrame(draw);
})();
}); // end DOMContentLoaded
