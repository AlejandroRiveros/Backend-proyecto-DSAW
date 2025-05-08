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
const app = express();
const PORT = 3001;
const Order = require('./Order');

const allowedOrigins = [
  'https://frontend-dsaw.vercel.app',
  'https://frontend-dsaw-*.vercel.app'
];

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  },
  transports: ['websocket'],
});

io.on('connection', (socket) => {
  console.log('Cliente conectado:', socket.id);

  socket.on('disconnect', () => {
    console.log('Cliente desconectado:', socket.id);
  });
});

const resetTokens = {}; // Almacén temporal para tokens de restablecimiento

app.use(express.json());
app.use(cors({
  origin: allowedOrigins,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true,
}));

const allowedDomains = ['unisabana.edu.co', 'possabana.com'];

const getUsersFile = (email) => {
  return email.endsWith('@unisabana.edu.co') ? './clientes.json' : './pos.json';
};

// Conexión a la base de datos MongoDB
mongoose.connect('mongodb://localhost:27017/inventoryDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

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
  const token = req.headers['authorization'];
  if (!token) return res.status(403).send('Token no proporcionado.');

  jwt.verify(token.split(' ')[1], process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).send('Token inválido.');
    req.user = decoded;
    next();
  });
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
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).send('Faltan datos.');

  if (!allowedDomains.some(domain => email.endsWith(`@${domain}`)) || email.endsWith('@possabana.com')) {
    return res.status(400).send('Solo se permiten correos de dominios autorizados, excepto POS.');
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const role = email.endsWith('@unisabana.edu.co') ? 'Cliente' : 'POS';
  const filePath = role === 'Cliente' ? './clientes.json' : './pos.json';

  const users = fs.existsSync(filePath) ? JSON.parse(fs.readFileSync(filePath, 'utf-8')) : [];

  if (users.find(user => user.email === email)) {
    return res.status(400).send('El usuario ya existe.');
  }

  users.push({ email, password: hashedPassword });
  fs.writeFileSync(filePath, JSON.stringify(users, null, 2)); // Formato legible con 2 espacios

  res.status(201).send('Usuario registrado exitosamente.');
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
    res.status(500).send('Error al obtener el producto.');
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
    res.status(500).send('Error al guardar el producto.');
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
    res.status(500).send('Error al insertar el producto de prueba.');
  }
});

// Implementar una caché en memoria para el endpoint /products
const cache = {};

app.get('/products', async (req, res) => {
  const { name, category } = req.query;
  const cacheKey = `${name || ''}-${category || ''}`;

  // Verificar si los datos están en la caché
  if (cache[cacheKey]) {
    console.log('Datos obtenidos de la caché');
    return res.json(cache[cacheKey]);
  }

  try {
    // Construir el filtro dinámico
    const filter = {};
    if (name) {
      filter.name = { $regex: name, $options: 'i' }; // Búsqueda insensible a mayúsculas
    }
    if (category) {
      filter.category = category;
    }

    // Consultar la base de datos con el filtro
    const products = await Product.find(filter);

    // Almacenar los datos en la caché
    cache[cacheKey] = products;

    res.json(products);
  } catch (error) {
    console.error('Error al filtrar productos:', error);
    res.status(500).json({ error: 'Error al filtrar productos' });
  }
});

// Ruta para crear un pedido y actualizar stock
app.post('/orders', async (req, res) => {
  const { products } = req.body;

  // 1. Verificar disponibilidad y actualizar stock
  const session = await mongoose.startSession();
  session.startTransaction();
  try {
    let total = 0;
    for (const item of products) {
      const product = await Product.findById(item.productId).session(session);
      if (!product || product.stock < item.quantity) {
        await session.abortTransaction();
        return res.status(400).json({ error: `No hay suficiente stock de ${item.name}` });
      }
      product.stock -= item.quantity;
      await product.save({ session });
      total += item.price * item.quantity;
    }

    // 2. Crear el pedido
    const order = new Order({
      products,
      total,
      status: 'pendiente'
    });
    await order.save({ session });

    await session.commitTransaction();
    session.endSession();

    res.status(201).json({ message: 'Pedido creado exitosamente', order });
  } catch (error) {
    await session.abortTransaction();
    session.endSession();
    res.status(500).json({ error: 'Error al crear el pedido' });
  }
});

// Obtener todos los pedidos
app.get('/orders', async (req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 });
    res.json(orders);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener los pedidos' });
  }
});

// Actualizar el estado de un pedido
app.put('/orders/:id', async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  try {
    const order = await Order.findByIdAndUpdate(id, { status }, { new: true });
    if (!order) {
      return res.status(404).json({ error: 'Pedido no encontrado' });
    }
    // Aquí podrías emitir un evento con socket.io para notificar al cliente
    res.json(order);
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar el pedido' });
  }
});

// --- Invalidar caché después de cambios en productos ---
const invalidateProductCache = () => {
  Object.keys(cache).forEach(key => delete cache[key]);
};

server.listen(3001, () => {
  console.log('Servidor escuchando en el puerto 3001');
});