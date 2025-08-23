import * as util from './index.js';

let hash = await util.hashFile('test.json');
console.log(hash);
