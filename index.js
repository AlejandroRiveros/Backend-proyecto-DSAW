process.on('uncaughtException', err => {
  console.error('Uncaught Exception:', err);
});
process.on('unhandledRejection', err => {
  console.error('Unhandled Rejection:', err);
});

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

const app = express();
const PORT = process.env.PORT || 3001;
const Order = require('./Order');

const allowedOrigins = [
  'https://frontend-dsaw.vercel.app',
  'https://frontend-proyecto-dsaw.vercel.app'
];
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('No permitido por CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true
}));
app.options('*', cors());
app.use(express.json());

const resetTokens = {};
const allowedDomains = ['unisabana.edu.co', 'possabana.com'];
const getUsersFile = (email) => {
  return email.endsWith('@unisabana.edu.co') ? './clientes.json' : './pos.json';
};

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 30000,
})
  .then(() => console.log('Conexión exitosa a MongoDB Atlas'))
  .catch((error) => console.error('Error al conectar a MongoDB Atlas:', error));

mongoose.set('strictQuery', false);

const productSchema = new mongoose.Schema({
  name: String,
  price: Number,
  stock: Number,
  category: String,
  image: String,
  restaurant: String,
});
const Product = mongoose.model('Product', productSchema);

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});
const upload = multer({ storage });

const restaurantSchema = new mongoose.Schema({
  name: String,
  horario: String,
  image: String,
  icon: String,
  menu: String
});
const Restaurant = mongoose.model('Restaurant', restaurantSchema);

app.post('/restaurants', async (req, res) => {
  const { name, horario, image, icon, menu } = req.body;
  try {
    const newRestaurant = new Restaurant({ name, horario, image, icon, menu });
    const saved = await newRestaurant.save();
    res.status(201).json(saved);
  } catch (error) {
    console.error('Error al guardar restaurante:', error);
    res.status(500).send('Error al guardar restaurante.');
  }
});

app.get('/restaurants', async (req, res) => {
  try {
    const all = await Restaurant.find();
    res.status(200).json(all);
  } catch (error) {
    res.status(500).send('Error al obtener restaurantes.');
  }
});
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
  setHeaders: (res) => {
    res.setHeader('Cache-Control', 'public, max-age=31536000');
  },
}));

function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).send('Token no proporcionado.');

  jwt.verify(token.split(' ')[1], process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).send('Token inválido.');
    req.user = decoded;
    next();
  });
}

function verifyRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).send('Acceso denegado. No tienes el rol adecuado.');
    }
    next();
  };
}

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
  fs.writeFileSync(filePath, JSON.stringify(users, null, 2));

  res.status(201).send('Usuario registrado exitosamente.');
});

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
  resetTokens[token] = email;

  console.log(`Enlace de restablecimiento: http://localhost:3000/reset-password?token=${token}`);
  res.send('Se ha enviado un enlace para restablecer la contraseña a su correo.');
});

app.post('/reset-password', async (req, res) => {
  const { token, password } = req.body;

  if (!resetTokens[token]) {
    return res.status(400).send('Token inválido o expirado.');
  }

  const email = resetTokens[token];
  delete resetTokens[token];

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

const inventoryCache = {};
app.post('/inventory', async (req, res) => {
  const { name, price, stock, category, restaurant, image } = req.body;

  try {
    const newProduct = new Product({ name, price, stock, category, restaurant, image });
    const savedProduct = await newProduct.save();
    invalidateInventoryCache();
    res.status(201).json(savedProduct);
  } catch (error) {
    console.error('Error al guardar el producto:', error);
    res.status(500).send('Error al guardar el producto.');
  }
});


const invalidateInventoryCache = () => {
  delete inventoryCache['inventory'];
};

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
    { new: true }
  );

  if (!updatedProduct) {
    return res.status(404).send('Producto no encontrado.');
  }

  invalidateInventoryCache();
  res.status(200).send('Producto actualizado');
});

app.delete('/inventory/:id', async (req, res) => {
  const { id } = req.params;
  await Product.findByIdAndDelete(id);
  invalidateInventoryCache();
  invalidateProductCache();
  res.send('Producto eliminado exitosamente.');
});

app.delete('/restaurants/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const deleted = await Restaurant.findByIdAndDelete(id);
    if (!deleted) {
      return res.status(404).send('Restaurante no encontrado');
    }
    res.send('Restaurante eliminado exitosamente');
  } catch (error) {
    console.error('Error al eliminar restaurante:', error);
    res.status(500).send('Error al eliminar restaurante');
  }
});

app.get('/protected', verifyToken, (req, res) => {
  res.send(`Hola ${req.user.username}, tienes acceso a esta ruta protegida.`);
});

app.get('/cliente', verifyToken, verifyRole('Cliente'), (req, res) => {
  res.send('Bienvenido, Cliente. Tienes acceso a esta ruta.');
});

app.get('/pos', verifyToken, verifyRole('POS'), (req, res) => {
  res.send('Bienvenido, POS. Tienes acceso a esta ruta.');
});

app.get('/', (req, res) => {
  console.log('Petición recibida en / (root endpoint)');
  res.send('Servidor backend funcionando correctamente');
});

console.log('Preparando para iniciar el servidor...');
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor escuchando en el puerto ${PORT}`);
});
console.log('app.listen() fue llamado, el proceso sigue vivo.');

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

const cache = {};

app.get('/products', async (req, res) => {
  const { name, category } = req.query;
  const cacheKey = `${name || ''}-${category || ''}`;

  console.log('Recibida solicitud para /products con parámetros:', { name, category });

  if (cache[cacheKey]) {
    console.log('Datos obtenidos de la caché');
    return res.json(cache[cacheKey]);
  }

  try {
    const filter = {};
    if (name) {
      filter.name = { $regex: name, $options: 'i' };
    }
    if (category) {
      filter.category = category;
    }

    console.log('Filtro construido:', filter);

    const products = await Product.find(filter);

    if (!products || products.length === 0) {
      console.log('No se encontraron productos');
      return res.status(404).json({ message: 'No se encontraron productos' });
    }

    console.log('Productos obtenidos de la base de datos:', products);

    cache[cacheKey] = products;

    res.json(products);
  } catch (error) {
    console.error('Error al filtrar productos:', error);
    res.status(500).json({ error: 'Error al filtrar productos' });
  }
});

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

app.post('/products', async (req, res) => {
  console.log('POST /products llamado');
  console.log('Body recibido:', req.body);
  const { name, price, stock, category, restaurant, image } = req.body;
  try {
    const newProduct = new Product({ name, price, stock, category, restaurant, image });
    const savedProduct = await newProduct.save();
    console.log('Producto guardado en MongoDB:', savedProduct);
    res.status(201).json(savedProduct);
  } catch (error) {
    console.error('Error al guardar el producto en /products:', error);
    res.status(500).send('Error al guardar el producto.');
  }
});
