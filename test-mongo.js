const mongoose = require('mongoose');
mongoose.connect('mongodb+srv://alejandrorivsob:Majo1811@alejo18.znsakxl.mongodb.net/InventoryDB?retryWrites=true&w=majority&appName=Alejo18')
  .then(() => console.log('Conexión exitosa'))
  .catch(err => console.error('Error:', err));