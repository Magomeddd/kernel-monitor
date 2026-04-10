const express = require('express');
const multer = require('multer');
const cors = require('cors');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.static('public'));

const upload = multer({ dest: '/tmp/uploads/' });

function analyzeWithStrace(filepath, filename) {
    return new Promise((resolve) => {
        const logs = [];
        
        try {
            fs.chmodSync(filepath, 0o755);
        } catch(e) {}
        
        const cmd = `timeout 5 strace -f -e trace=open,openat,read,write,connect,execve,fork,clone,mmap -s 200 "${filepath}" 2>&1 | head -100`;
        
        exec(cmd, { timeout: 6000 }, (error, stdout, stderr) => {
            const output = (stdout || stderr || '');
            const lines = output.split('\n');
            
            let pid = Math.floor(Math.random() * 30000) + 1000;
            let timeCounter = 0;
            
            for (let i = 0; i < lines.length && i < 60; i++) {
                const line = lines[i];
                if (!line.trim()) continue;
                
                timeCounter++;
                const timeStr = `00:00:${String(timeCounter).padStart(2, '0')}`;
                
                let action = 'CALL';
                let detail = line.substring(0, 120);
                let suspicious = false;
                
                if (line.includes('open(') || line.includes('openat(')) {
                    action = 'OPEN';
                    const match = line.match(/"([^"]+)"/);
                    detail = match ? match[1] : line.substring(0, 80);
                    const susp = ['/etc/passwd', '/etc/shadow', '.ssh', 'id_rsa', '/proc/self/mem', '/dev/mem'];
                    if (susp.some(s => detail.includes(s))) suspicious = true;
                }
                else if (line.includes('read(')) {
                    action = 'READ';
                    const match = line.match(/read\((\d+),/);
                    detail = `fd=${match ? match[1] : '?'}`;
                }
                else if (line.includes('write(')) {
                    action = 'WRITE';
                    const match = line.match(/write\((\d+),/);
                    detail = `fd=${match ? match[1] : '?'}`;
                }
                else if (line.includes('connect(')) {
                    action = 'CONNECT';
                    const ipMatch = line.match(/(\d+\.\d+\.\d+\.\d+):(\d+)/);
                    detail = ipMatch ? `${ipMatch[1]}:${ipMatch[2]}` : line.substring(0, 60);
                    if (ipMatch) suspicious = true;
                }
                else if (line.includes('execve(')) {
                    action = 'EXEC';
                    const match = line.match(/"([^"]+)"/);
                    detail = match ? match[1] : 'unknown';
                }
                else if (line.includes('fork(') || line.includes('clone(')) {
                    action = 'FORK';
                    detail = 'new process';
                }
                else if (line.includes('mmap(')) {
                    action = 'MMAP';
                    detail = 'memory allocation';
                }
                else {
                    continue;
                }
                
                logs.push({
                    time: timeStr,
                    pid: pid,
                    action: action,
                    detail: detail,
                    suspicious: suspicious
                });
            }
            
            if (logs.length === 0) {
                logs.push({
                    time: '00:00:01',
                    pid: pid,
                    action: 'INFO',
                    detail: 'No syscalls detected. File may be static or requires arguments.',
                    suspicious: false
                });
            }
            
            resolve(logs);
        });
    });
}

app.post('/analyze', upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const filepath = req.file.path;
    const filename = req.file.originalname;
    const fileSize = req.file.size;
    const fileHash = crypto.createHash('md5').update(fs.readFileSync(filepath)).digest('hex').substring(0, 8);
    
    const logs = await analyzeWithStrace(filepath, filename);
    
    const summary = {
        total_calls: logs.length,
        file_ops: logs.filter(l => ['OPEN', 'READ', 'WRITE'].includes(l.action)).length,
        network_ops: logs.filter(l => l.action === 'CONNECT').length,
        process_ops: logs.filter(l => ['FORK', 'EXEC'].includes(l.action)).length,
        suspicious: logs.filter(l => l.suspicious).length,
        pid: logs[0]?.pid || 'unknown',
        filename: filename,
        filesize: fileSize,
        hash: fileHash
    };
    
    try {
        fs.unlinkSync(filepath);
    } catch(e) {}
    
    res.json({ summary: summary, logs: logs });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});