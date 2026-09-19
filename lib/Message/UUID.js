var UUID = function (binaryData, offset) {
    if (!Buffer.isBuffer(binaryData) || !Number.isInteger(offset) || offset < 0 ||
        binaryData.length - offset < 16) throw new RangeError('Truncated UUID');
    this.string = binaryData.readUInt32LE(offset).toString(16).padStart(8, '0') + '-'
        + binaryData.readUInt16LE(offset + 4).toString(16).padStart(4, '0') + '-'
        + binaryData.readUInt16LE(offset + 6).toString(16).padStart(4, '0') + '-'
        + binaryData.toString('hex', offset + 8, offset + 16);
    this.data_length = 16;
};

module.exports = UUID;
