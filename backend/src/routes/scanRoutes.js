const express = require('express');
const router = express.Router();
const scanController = require('../controllers/scanController');

router.post('/', scanController.scanUrl);

module.exports = router;
