require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const bcrypt = require('bcrypt');
const cors = require('cors');
const crypto = require('crypto');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
const admin = require('firebase-admin');
const app = express();
const PORT = process.env.PORT || 3001;
const Order = require('./Order');

// Verificar variables de entorno necesarias
if (!process.env.JWT_SECRET || !process.env.JWT_EXPIRES_IN) {
  console.error('Error: JWT_SECRET y JWT_EXPIRES_IN deben estar definidos en el archivo .env');
  process.exit(1);
}

// Verificar y crear directorio de uploads si no existe
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Inicialización de Firebase Admin
try {
  if (!process.env.FIREBASE_CREDENTIALS) {
    throw new Error('FIREBASE_CREDENTIALS no está definido en las variables de entorno');
  }

  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    }),
  });
  
} catch (error) {
  console.error('Error al inicializar Firebase Admin:', error);
  process.exit(1);
}

const sendNotification = async (token, title, body) => {
  const message = {
    notification: {
      title,
      body,
    },
    token,
  };

  try {
    const response = await admin.messaging().send(message);
    console.log('Notificación enviada:', response);
  } catch (error) {
    console.error('Error al enviar la notificación:', error);
  }
};

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: 'http://localhost:5173', // Permitir solicitudes desde el frontend
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
  },
  transports: ['websocket'], // Forzar el uso de WebSockets
});

io.on('connection', (socket) => {
  console.log('Cliente conectado:', socket.id);

  socket.on('disconnect', () => {
    console.log('Cliente desconectado:', socket.id);
  });
});

const resetTokens = {}; // Almacén temporal para tokens de restablecimiento

app.use(express.json());
app.use(cors());

const allowedDomains = ['unisabana.edu.co', 'possabana.com'];

const getUsersFile = (email) => {
  return email.endsWith('@unisabana.edu.co') ? './clientes.json' : './pos.json';
};

// Conexión a MongoDB Atlas con mejor manejo de errores
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://alejandrorivsob:tS6OnQ6IMl1J4xt9@alejo18.znsakxl.mongodb.net/InventoryDB?retryWrites=true&w=majority', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 30000,
})
  .then(() => console.log('Conexión exitosa a MongoDB Atlas'))
  .catch((error) => {
    console.error('Error al conectar a MongoDB Atlas:', error);
    process.exit(1);
  });

mongoose.set('strictQuery', false); // Desactivar strictQuery para evitar problemas con consultas

const productSchema = new mongoose.Schema({
  name: String,
  price: Number,
  stock: Number,
  category: String,
  image: String,
});

const Product = mongoose.model('Product', productSchema);

// Configuración de multer para guardar imágenes
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // Carpeta donde se guardarán las imágenes
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const upload = multer({ storage });

// Configurar encabezados de caché para recursos estáticos
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
  setHeaders: (res) => {
    res.setHeader('Cache-Control', 'public, max-age=31536000'); // 1 año
  },
}));

// Middleware para verificar JWT
function verifyToken(req, res, next) {
  try {
    const token = req.headers['authorization'];
    if (!token) {
      return res.status(403).json({ error: 'Token no proporcionado.' });
    }

    const tokenParts = token.split(' ');
    if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer') {
      return res.status(401).json({ error: 'Formato de token inválido.' });
    }

    jwt.verify(tokenParts[1], process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(401).json({ error: 'Token inválido o expirado.' });
      }
      req.user = decoded;
      next();
    });
  } catch (error) {
    console.error('Error en verifyToken:', error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
}

// Middleware para verificar roles
function verifyRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).send('Acceso denegado. No tienes el rol adecuado.');
    }
    next();
  };
}

// Ruta para registrar usuarios
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Faltan datos requeridos.' });
    }

    // Validar formato de email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Formato de correo electrónico inválido.' });
    }

    if (!allowedDomains.some(domain => email.endsWith(`@${domain}`)) || email.endsWith('@possabana.com')) {
      return res.status(400).json({ error: 'Solo se permiten correos de dominios autorizados, excepto POS.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const role = email.endsWith('@unisabana.edu.co') ? 'Cliente' : 'POS';
    const filePath = role === 'Cliente' ? './clientes.json' : './pos.json';

    // Asegurarse de que el archivo existe
    if (!fs.existsSync(filePath)) {
      fs.writeFileSync(filePath, JSON.stringify([]));
    }

    const users = JSON.parse(fs.readFileSync(filePath, 'utf-8'));

    if (users.find(user => user.email === email)) {
      return res.status(400).json({ error: 'El usuario ya existe.' });
    }

    users.push({ email, password: hashedPassword });
    fs.writeFileSync(filePath, JSON.stringify(users, null, 2));

    res.status(201).json({ message: 'Usuario registrado exitosamente.' });
  } catch (error) {
    console.error('Error en registro:', error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

// Ruta para iniciar sesión
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).send('Faltan datos.');

  if (!allowedDomains.some(domain => email.endsWith(`@${domain}`))) {
    return res.status(400).send('Solo se permiten correos de dominios autorizados.');
  }

  const users = JSON.parse(fs.readFileSync(getUsersFile(email), 'utf-8'));
  const user = users.find(user => user.email === email);

  if (!user) {
    return res.status(404).send('El correo no está registrado.');
  }

  if (!(await bcrypt.compare(password, user.password))) {
    return res.status(401).send('Contraseña incorrecta.');
  }

  const role = email.endsWith('@unisabana.edu.co') ? 'Cliente' : 'POS';
  const token = jwt.sign({ email, role }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });

  res.json({ token });
});

// Ruta para solicitar restablecimiento de contraseña
app.post('/forgot-password', (req, res) => {
  const { email } = req.body;
  if (!allowedDomains.some(domain => email.endsWith(`@${domain}`))) {
    return res.status(400).send('Solo se permiten correos de dominios autorizados.');
  }

  const users = JSON.parse(fs.readFileSync(getUsersFile(email), 'utf-8'));
  const user = users.find(user => user.email === email);

  if (!user) {
    return res.status(404).send('El correo no está registrado.');
  }

  const token = crypto.randomBytes(32).toString('hex');
  resetTokens[token] = email; // Asociar el token al correo

  console.log(`Enlace de restablecimiento: http://localhost:3000/reset-password?token=${token}`);
  res.send('Se ha enviado un enlace para restablecer la contraseña a su correo.');
});

// Ruta para restablecer la contraseña
app.post('/reset-password', async (req, res) => {
  const { token, password } = req.body;

  if (!resetTokens[token]) {
    return res.status(400).send('Token inválido o expirado.');
  }

  const email = resetTokens[token];
  delete resetTokens[token]; // Eliminar el token después de usarlo

  const users = JSON.parse(fs.readFileSync(getUsersFile(email), 'utf-8'));
  const userIndex = users.findIndex(user => user.email === email);

  if (userIndex === -1) {
    return res.status(404).send('Usuario no encontrado.');
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  users[userIndex].password = hashedPassword;
  fs.writeFileSync(getUsersFile(email), JSON.stringify(users));

  res.send('Contraseña restablecida exitosamente.');
});

// Rutas para la gestión de inventarios
app.get('/inventory', async (req, res) => {
  const products = await Product.find();
  res.json(products);
});

// Ruta para obtener un producto específico por ID
app.get('/inventory/:id', async (req, res) => {
  const { id } = req.params;
  if (!mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).send('ID de producto no válido.');
  }

  try {
    const product = await Product.findById(id);
    if (!product) {
      return res.status(404).send('Producto no encontrado.');
    }
    res.json(product);
  } catch (error) {
    res.status(500).json({ error: 'Ocurrió un error inesperado. Por favor, intenta nuevamente más tarde.' });
  }
});

// Ruta para agregar un producto con imagen
app.post('/inventory', upload.single('image'), async (req, res) => {
  const { name, price, stock, category } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : '';

  try {
    const newProduct = new Product({ name, price, stock, category, image: imageUrl });
    const savedProduct = await newProduct.save();
    invalidateProductCache();
    res.status(201).json(savedProduct);
  } catch (error) {
    console.error('Error al guardar el producto:', error);
    res.status(500).json({ error: 'Ocurrió un error inesperado. Por favor, intenta nuevamente más tarde.' });
  }
});

app.put('/inventory/:id', async (req, res) => {
  const { id } = req.params;
  const { name, price, stock, category } = req.body;
  console.log("Datos recibidos para actualizar:", { name, price, stock, category });
  console.log("ID del producto a actualizar:", id);

  const parsedPrice = parseFloat(price);
  const parsedStock = parseInt(stock, 10);

  const updatedProduct = await Product.findByIdAndUpdate(
    id,
    { name, price: parsedPrice, stock: parsedStock, category },
    { new: true } // Esto asegura que se devuelva el producto actualizado
  );

  if (!updatedProduct) {
    return res.status(404).send('Producto no encontrado.');
  }

  invalidateProductCache();
  io.emit('product-updated', updatedProduct);
  res.status(200).send('Producto actualizado');
});

app.delete('/inventory/:id', async (req, res) => {
  const { id } = req.params;
  await Product.findByIdAndDelete(id);
  invalidateProductCache();
  res.send('Producto eliminado exitosamente.');
});

// Ruta protegida de ejemplo
app.get('/protected', verifyToken, (req, res) => {
  res.send(`Hola ${req.user.username}, tienes acceso a esta ruta protegida.`);
});

// Ruta protegida para Clientes
app.get('/cliente', verifyToken, verifyRole('Cliente'), (req, res) => {
  res.send('Bienvenido, Cliente. Tienes acceso a esta ruta.');
});

// Ruta protegida para POS
app.get('/pos', verifyToken, verifyRole('POS'), (req, res) => {
  res.send('Bienvenido, POS. Tienes acceso a esta ruta.');
});

app.get('/', (req, res) => {
  res.send('Servidor backend funcionando correctamente');
});

// Script de prueba para insertar un producto en MongoDB
app.get('/test-insert', async (req, res) => {
  try {
    const testProduct = new Product({
      name: 'Producto de prueba',
      price: 100,
      stock: 10,
      category: 'Pruebas',
    });
    const savedProduct = await testProduct.save();
    res.json({ message: 'Producto de prueba insertado correctamente', product: savedProduct });
  } catch (error) {
    console.error('Error al insertar el producto de prueba:', error);
    res.status(500).json({ error: 'Ocurrió un error inesperado. Por favor, intenta nuevamente más tarde.' });
  }
});

// Implementar una caché en memoria para el endpoint /products
const cache = {};

// Actualizar el endpoint /products para manejar mejor los errores y devolver datos
app.get('/products', async (req, res) => {
  try {
    const { name, category } = req.query;
    const cacheKey = `${name || ''}-${category || ''}`;

    if (cache[cacheKey]) {
      return res.json(cache[cacheKey]);
    }

    const filter = {};
    if (name) {
      filter.name = { $regex: name, $options: 'i' };
    }
    if (category) {
      filter.category = category;
    }

    const products = await Product.find(filter);

    if (!products || products.length === 0) {
      return res.status(404).json({ message: 'No se encontraron productos' });
    }

    cache[cacheKey] = products;
    res.json(products);
  } catch (error) {
    console.error('Error al obtener productos:', error);
    res.status(500).json({ error: 'Error interno del servidor al obtener productos.' });
  }
});

// Ruta para crear un pedido y actualizar stock
app.post('/orders', async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    const { products } = req.body;

    if (!products || !Array.isArray(products) || products.length === 0) {
      await session.abortTransaction();
      return res.status(400).json({ error: 'Se requiere una lista válida de productos.' });
    }

    let total = 0;
    for (const item of products) {
      const product = await Product.findById(item.productId).session(session);
      if (!product) {
        await session.abortTransaction();
        return res.status(404).json({ error: `Producto no encontrado: ${item.productId}` });
      }
      if (product.stock < item.quantity) {
        await session.abortTransaction();
        return res.status(400).json({ error: `Stock insuficiente para ${product.name}` });
      }
      product.stock -= item.quantity;
      await product.save({ session });
      total += item.price * item.quantity;
    }

    const order = new Order({
      products,
      total,
      status: 'pendiente'
    });
    await order.save({ session });

    await session.commitTransaction();
    res.status(201).json({ message: 'Pedido creado exitosamente', order });
  } catch (error) {
    await session.abortTransaction();
    console.error('Error al crear pedido:', error);
    res.status(500).json({ error: 'Error interno del servidor al crear el pedido.' });
  } finally {
    session.endSession();
  }
});

// Obtener todos los pedidos
app.get('/orders', async (req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 });
    res.json(orders);
  } catch (error) {
    res.status(500).json({ error: 'Ocurrió un error inesperado. Por favor, intenta nuevamente más tarde.' });
  }
});

// Actualizar el estado de un pedido
app.put('/orders/:id', async (req, res) => {
  const { id } = req.params;
  const { status, token } = req.body;

  try {
    const order = await Order.findByIdAndUpdate(id, { status }, { new: true });
    if (!order) {
      return res.status(404).json({ error: 'Pedido no encontrado' });
    }

    if (token) {
      await sendNotification(token, 'Estado del pedido actualizado', `Tu pedido ahora está: ${status}`);
    }

    res.json(order);
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar el pedido' });
  }
});

app.put('/orders/:id/cancel', async (req, res) => {
  const { id } = req.params;

  const session = await mongoose.startSession();
  session.startTransaction();
  try {
    const order = await Order.findById(id).session(session);

    if (!order) {
      await session.abortTransaction();
      return res.status(404).json({ error: 'Pedido no encontrado' });
    }

    if (order.status === 'cancelado') {
      await session.abortTransaction();
      return res.status(400).json({ error: 'El pedido ya está cancelado' });
    }

    // Revertir el stock de los productos
    for (const item of order.products) {
      const product = await Product.findById(item.productId).session(session);
      if (product) {
        product.stock += item.quantity;
        await product.save({ session });
      }
    }

    // Actualizar el estado del pedido a cancelado
    order.status = 'cancelado';
    await order.save({ session });

    await session.commitTransaction();
    session.endSession();

    res.json({ message: 'Pedido cancelado y stock revertido correctamente', order });
  } catch (error) {
    await session.abortTransaction();
    session.endSession();
    console.error('Error al cancelar el pedido:', error);
    res.status(500).json({ error: 'Error interno del servidor al cancelar el pedido' });
  }
});

// --- Invalidar caché después de cambios en productos ---
const invalidateProductCache = () => {
  Object.keys(cache).forEach(key => delete cache[key]);
};

app.post('/inventory/validate-stock', async (req, res) => {
  const { products } = req.body;

  if (!products || !Array.isArray(products)) {
    return res.status(400).json({ error: 'Formato de datos inválido. Se esperaba un array de productos.' });
  }

  try {
    const validationResults = [];

    for (const product of products) {
      const dbProduct = await Product.findById(product.productId);

      if (!dbProduct) {
        validationResults.push({ productId: product.productId, valid: false, message: 'Producto no encontrado.' });
        continue;
      }

      if (dbProduct.stock < product.quantity) {
        validationResults.push({
          productId: product.productId,
          valid: false,
          message: `Stock insuficiente. Disponible: ${dbProduct.stock}, solicitado: ${product.quantity}.`,
        });
        continue;
      }

      validationResults.push({ productId: product.productId, valid: true });
    }

    const invalidResults = validationResults.filter((result) => !result.valid);

    if (invalidResults.length > 0) {
      return res.status(400).json({ error: 'Validación de stock fallida.', details: invalidResults });
    }

    res.json({ message: 'Stock validado correctamente.' });
  } catch (error) {
    console.error('Error al validar el stock:', error);
    res.status(500).json({ error: 'Error interno del servidor al validar el stock.' });
  }
});

server.listen(PORT, () => {
  console.log(`Servidor escuchando en el puerto ${PORT}`);
}).on('error', (error) => {
  console.error('Error al iniciar el servidor:', error);
  process.exit(1);
});