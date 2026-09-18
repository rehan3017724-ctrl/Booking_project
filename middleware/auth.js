function requireLogin(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    next();
}

function requireAdmin(req, res, next) {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).send('Access denied');
    }

    next();
}

function requireOwner(req, res, next) {
    if (!req.session.user || req.session.user.role !== 'owner') {
        return res.status(403).send('Access denied');
    }

    next();
}

module.exports = {
    requireLogin,
    requireAdmin,
    requireOwner
};
