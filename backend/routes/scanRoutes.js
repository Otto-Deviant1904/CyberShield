const express = require('express');

const { handleScan } = require('../controllers/scanController');
const { validateScanRequest } = require('../middleware/validateScanRequest');

const router = express.Router();

router.post('/', validateScanRequest, handleScan);

module.exports = router;
