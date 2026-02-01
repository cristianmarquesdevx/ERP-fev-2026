// ==================================================
// SISTEMA ERP COMPLETO - BACKEND E FRONTEND UNIFICADO
// ==================================================

// ======================
// BACKEND (Node.js/Express)
// ======================

// Carrega variáveis de ambiente
require('dotenv').config();

// Importa dependências
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes } = require('sequelize');

// Configurações
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'secret_key_erp_sistema';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ======================
// BANCO DE DADOS (SQLite em memória)
// ======================

const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: ':memory:',
  logging: false
});

// ======================
// MODELOS
// ======================

const User = sequelize.define('User', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  name: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  password: { type: DataTypes.STRING, allowNull: false },
  role: { type: DataTypes.ENUM('admin', 'operador'), defaultValue: 'operador' }
}, { tableName: 'users', timestamps: false });

const Client = sequelize.define('Client', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  name: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  phone: { type: DataTypes.STRING, allowNull: false },
  address: { type: DataTypes.STRING, allowNull: false }
}, { tableName: 'clients', timestamps: false });

const Product = sequelize.define('Product', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  name: { type: DataTypes.STRING, allowNull: false },
  description: { type: DataTypes.TEXT },
  price: { type: DataTypes.DECIMAL(10, 2), allowNull: false },
  stock: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 }
}, { tableName: 'products', timestamps: false });

const Sale = sequelize.define('Sale', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  clientId: { type: DataTypes.INTEGER, allowNull: false },
  total: { type: DataTypes.DECIMAL(10, 2), allowNull: false },
  date: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
}, { tableName: 'sales', timestamps: false });

const SaleItem = sequelize.define('SaleItem', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  saleId: { type: DataTypes.INTEGER, allowNull: false },
  productId: { type: DataTypes.INTEGER, allowNull: false },
  quantity: { type: DataTypes.INTEGER, allowNull: false },
  price: { type: DataTypes.DECIMAL(10, 2), allowNull: false }
}, { tableName: 'sale_items', timestamps: false });

const Financial = sequelize.define('Financial', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  type: { type: DataTypes.ENUM('entrada', 'saida'), allowNull: false },
  amount: { type: DataTypes.DECIMAL(10, 2), allowNull: false },
  description: { type: DataTypes.STRING, allowNull: false },
  date: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
}, { tableName: 'financials', timestamps: false });

// ======================
// RELACIONAMENTOS
// ======================

Sale.belongsTo(Client, { foreignKey: 'clientId' });
Client.hasMany(Sale, { foreignKey: 'clientId' });
Sale.hasMany(SaleItem, { foreignKey: 'saleId' });
SaleItem.belongsTo(Sale, { foreignKey: 'saleId' });
SaleItem.belongsTo(Product, { foreignKey: 'productId' });
Product.hasMany(SaleItem, { foreignKey: 'productId' });

// ======================
// MIDDLEWARES
// ======================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

const authorizeAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  next();
};

// ======================
// ROTAS DE AUTENTICAÇÃO
// ======================

// Registro de usuário
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashedPassword, role });
    res.status(201).json({ id: user.id, name: user.name, email: user.email, role: user.role });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ where: { email } });
    if (!user) return res.status(400).json({ error: 'Usuário não encontrado' });
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: 'Senha inválida' });
    
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ======================
// ROTAS DE USUÁRIOS (apenas admin)
// ======================

app.use('/api/users', authenticateToken, authorizeAdmin);

app.get('/api/users', async (req, res) => {
  try {
    const users = await User.findAll({ attributes: { exclude: ['password'] } });
    res.json(users);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/users/:id', async (req, res) => {
  try {
    const user = await User.findByPk(req.params.id, { attributes: { exclude: ['password'] } });
    if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
    res.json(user);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/users', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashedPassword, role });
    res.status(201).json({ id: user.id, name: user.name, email: user.email, role: user.role });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.put('/api/users/:id', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const user = await User.findByPk(req.params.id);
    if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
    
    user.name = name || user.name;
    user.email = email || user.email;
    user.role = role || user.role;
    if (password) user.password = await bcrypt.hash(password, 10);
    
    await user.save();
    res.json({ id: user.id, name: user.name, email: user.email, role: user.role });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete('/api/users/:id', async (req, res) => {
  try {
    const user = await User.findByPk(req.params.id);
    if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
    await user.destroy();
    res.json({ message: 'Usuário excluído com sucesso' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ======================
// ROTAS DE CLIENTES
// ======================

app.use('/api/clients', authenticateToken);

app.get('/api/clients', async (req, res) => {
  try {
    const clients = await Client.findAll();
    res.json(clients);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/clients/:id', async (req, res) => {
  try {
    const client = await Client.findByPk(req.params.id);
    if (!client) return res.status(404).json({ error: 'Cliente não encontrado' });
    res.json(client);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/clients', async (req, res) => {
  try {
    const { name, email, phone, address } = req.body;
    const client = await Client.create({ name, email, phone, address });
    res.status(201).json(client);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.put('/api/clients/:id', async (req, res) => {
  try {
    const { name, email, phone, address } = req.body;
    const client = await Client.findByPk(req.params.id);
    if (!client) return res.status(404).json({ error: 'Cliente não encontrado' });
    
    client.name = name || client.name;
    client.email = email || client.email;
    client.phone = phone || client.phone;
    client.address = address || client.address;
    
    await client.save();
    res.json(client);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete('/api/clients/:id', async (req, res) => {
  try {
    const client = await Client.findByPk(req.params.id);
    if (!client) return res.status(404).json({ error: 'Cliente não encontrado' });
    await client.destroy();
    res.json({ message: 'Cliente excluído com sucesso' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ======================
// ROTAS DE PRODUTOS
// ======================

app.use('/api/products', authenticateToken);

app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.findAll();
    res.json(products);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findByPk(req.params.id);
    if (!product) return res.status(404).json({ error: 'Produto não encontrado' });
    res.json(product);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/products', async (req, res) => {
  try {
    const { name, description, price, stock } = req.body;
    const product = await Product.create({ name, description, price, stock });
    res.status(201).json(product);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.put('/api/products/:id', async (req, res) => {
  try {
    const { name, description, price, stock } = req.body;
    const product = await Product.findByPk(req.params.id);
    if (!product) return res.status(404).json({ error: 'Produto não encontrado' });
    
    product.name = name || product.name;
    product.description = description || product.description;
    product.price = price || product.price;
    product.stock = stock || product.stock;
    
    await product.save();
    res.json(product);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete('/api/products/:id', async (req, res) => {
  try {
    const product = await Product.findByPk(req.params.id);
    if (!product) return res.status(404).json({ error: 'Produto não encontrado' });
    await product.destroy();
    res.json({ message: 'Produto excluído com sucesso' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ======================
// ROTAS DE VENDAS
// ======================

app.use('/api/sales', authenticateToken);

app.get('/api/sales', async (req, res) => {
  try {
    const sales = await Sale.findAll({
      include: [
        { model: Client },
        { model: SaleItem, include: [Product] }
      ]
    });
    res.json(sales);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/sales/:id', async (req, res) => {
  try {
    const sale = await Sale.findByPk(req.params.id, {
      include: [
        { model: Client },
        { model: SaleItem, include: [Product] }
      ]
    });
    if (!sale) return res.status(404).json({ error: 'Venda não encontrada' });
    res.json(sale);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/sales', async (req, res) => {
  try {
    const { clientId, items } = req.body;
    let total = 0;
    
    // Verifica estoque e calcula total
    for (const item of items) {
      const product = await Product.findByPk(item.productId);
      if (!product) return res.status(404).json({ error: `Produto ${item.productId} não encontrado` });
      if (product.stock < item.quantity) return res.status(400).json({ error: `Estoque insuficiente para ${product.name}` });
      total += item.price * item.quantity;
    }
    
    // Cria venda
    const sale = await Sale.create({ clientId, total });
    
    // Cria itens e atualiza estoque
    for (const item of items) {
      await SaleItem.create({
        saleId: sale.id,
        productId: item.productId,
        quantity: item.quantity,
        price: item.price
      });
      
      const product = await Product.findByPk(item.productId);
      product.stock -= item.quantity;
      await product.save();
    }
    
    // Registra entrada financeira
    await Financial.create({
      type: 'entrada',
      amount: total,
      description: `Venda #${sale.id}`
    });
    
    res.status(201).json(sale);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ======================
// ROTAS FINANCEIRAS (apenas admin)
// ======================

app.use('/api/financial', authenticateToken, authorizeAdmin);

app.get('/api/financial', async (req, res) => {
  try {
    const financials = await Financial.findAll();
    res.json(financials);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/financial/:id', async (req, res) => {
  try {
    const financial = await Financial.findByPk(req.params.id);
    if (!financial) return res.status(404).json({ error: 'Registro não encontrado' });
    res.json(financial);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/api/financial', async (req, res) => {
  try {
    const { type, amount, description } = req.body;
    const financial = await Financial.create({ type, amount, description });
    res.status(201).json(financial);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.put('/api/financial/:id', async (req, res) => {
  try {
    const { type, amount, description } = req.body;
    const financial = await Financial.findByPk(req.params.id);
    if (!financial) return res.status(404).json({ error: 'Registro não encontrado' });
    
    financial.type = type || financial.type;
    financial.amount = amount || financial.amount;
    financial.description = description || financial.description;
    
    await financial.save();
    res.json(financial);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.delete('/api/financial/:id', async (req, res) => {
  try {
    const financial = await Financial.findByPk(req.params.id);
    if (!financial) return res.status(404).json({ error: 'Registro não encontrado' });
    await financial.destroy();
    res.json({ message: 'Registro excluído com sucesso' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ======================
// ROTA PARA FRONTEND (HTML)
// ======================

app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Sistema ERP</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; font-family: Arial, sans-serif; }
            body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); height: 100vh; display: flex; justify-content: center; align-items: center; }
            .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 20px 40px rgba(0,0,0,0.2); text-align: center; max-width: 400px; width: 100%; }
            h1 { color: #333; margin-bottom: 30px; }
            .btn { display: inline-block; background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 10px; transition: background 0.3s; }
            .btn:hover { background: #764ba2; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🚀 Sistema ERP</h1>
            <p>Sistema completo de gestão empresarial</p>
            <div style="margin-top: 30px;">
                <a href="/login.html" class="btn">Login</a>
                <a href="/dashboard.html" class="btn">Dashboard</a>
            </div>
            <p style="margin-top: 20px; color: #666; font-size: 14px;">Backend rodando na porta ${PORT}</p>
        </div>
    </body>
    </html>
  `);
});

// ======================
// INICIALIZAÇÃO DO SISTEMA
// ======================

async function initializeSystem() {
  try {
    // Sincroniza banco de dados
    await sequelize.sync({ force: true });
    
    // Cria usuário admin padrão
    const hashedPassword = await bcrypt.hash('admin123', 10);
    await User.create({
      name: 'Administrador',
      email: 'admin@erp.com',
      password: hashedPassword,
      role: 'admin'
    });
    
    // Cria alguns dados de exemplo
    await Client.create({ name: 'Cliente Exemplo', email: 'cliente@exemplo.com', phone: '(11) 99999-9999', address: 'Rua Exemplo, 123' });
    await Product.create({ name: 'Produto A', description: 'Descrição do produto A', price: 99.90, stock: 50 });
    await Product.create({ name: 'Produto B', description: 'Descrição do produto B', price: 149.90, stock: 30 });
    
    console.log('✅ Banco de dados inicializado com sucesso!');
    console.log('👤 Usuário admin criado: admin@erp.com / admin123');
    
    // Inicia servidor
    app.listen(PORT, () => {
      console.log(`🚀 Servidor ERP rodando em: http://localhost:${PORT}`);
      console.log(`📁 API disponível em: http://localhost:${PORT}/api`);
    });
    
  } catch (error) {
    console.error('❌ Erro ao inicializar sistema:', error);
  }
}

initializeSystem();

// ======================
// FRONTEND (Arquivos estáticos)
// ======================

// Criando diretório público para arquivos estáticos
const fs = require('fs');
const path = require('path');

const publicDir = path.join(__dirname, 'public');
if (!fs.existsSync(publicDir)) {
  fs.mkdirSync(publicDir);
}

// HTML do Login
fs.writeFileSync(path.join(publicDir, 'login.html'), `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ERP - Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: Arial, sans-serif; }
        body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); height: 100vh; display: flex; justify-content: center; align-items: center; }
        .login-container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 20px 40px rgba(0,0,0,0.2); width: 100%; max-width: 400px; }
        h1 { color: #333; margin-bottom: 30px; text-align: center; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; color: #555; font-weight: bold; }
        input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 5px; font-size: 16px; }
        button { width: 100%; padding: 12px; background: #667eea; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; transition: background 0.3s; }
        button:hover { background: #764ba2; }
        .message { margin-top: 15px; padding: 10px; border-radius: 5px; text-align: center; }
        .error { background: #ffebee; color: #c62828; border: 1px solid #ffcdd2; }
        .success { background: #e8f5e9; color: #2e7d32; border: 1px solid #c8e6c9; }
        .demo-info { margin-top: 20px; padding: 15px; background: #f3f4f6; border-radius: 5px; font-size: 14px; color: #666; }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>🔐 Login ERP</h1>
        <form id="loginForm">
            <div class="form-group">
                <label for="email">E-mail:</label>
                <input type="email" id="email" value="admin@erp.com" required>
            </div>
            <div class="form-group">
                <label for="password">Senha:</label>
                <input type="password" id="password" value="admin123" required>
            </div>
            <button type="submit">Entrar</button>
        </form>
        <div id="message" class="message"></div>
        <div class="demo-info">
            <strong>Dados para teste:</strong><br>
            E-mail: admin@erp.com<br>
            Senha: admin123
        </div>
    </div>
    <script>
        document.getElementById('loginForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const messageDiv = document.getElementById('message');
            
            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email, password })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    localStorage.setItem('token', data.token);
                    localStorage.setItem('user', JSON.stringify(data.user));
                    messageDiv.textContent = 'Login realizado com sucesso! Redirecionando...';
                    messageDiv.className = 'message success';
                    setTimeout(() => window.location.href = '/dashboard.html', 1000);
                } else {
                    messageDiv.textContent = data.error || 'Erro ao fazer login';
                    messageDiv.className = 'message error';
                }
            } catch (error) {
                messageDiv.textContent = 'Erro de conexão com o servidor';
                messageDiv.className = 'message error';
            }
        });
        
        // Verifica se já está logado
        if (localStorage.getItem('token')) {
            window.location.href = '/dashboard.html';
        }
    </script>
</body>
</html>
`);

// HTML do Dashboard
fs.writeFileSync(path.join(publicDir, 'dashboard.html'), `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ERP - Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: Arial, sans-serif; }
        body { display: flex; min-height: 100vh; background: #f5f5f5; }
        .sidebar { width: 250px; background: #2c3e50; color: white; padding: 20px; }
        .sidebar h2 { margin-bottom: 30px; color: #ecf0f1; }
        .sidebar ul { list-style: none; }
        .sidebar li { margin-bottom: 15px; }
        .sidebar a { color: #bdc3c7; text-decoration: none; font-size: 16px; padding: 10px; display: block; border-radius: 5px; transition: all 0.3s; }
        .sidebar a:hover { background: #34495e; color: white; }
        .content { flex: 1; padding: 30px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        .header h1 { color: #2c3e50; }
        .user-info { background: white; padding: 15px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .logout-btn { background: #e74c3c; color: white; border: none; padding: 8px 15px; border-radius: 5px; cursor: pointer; }
        .dashboard-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
        .card h3 { color: #2c3e50; margin-bottom: 10px; }
        .card .value { font-size: 32px; font-weight: bold; color: #3498db; }
        .module-section { display: none; }
        .active-section { display: block; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #3498db; color: white; }
        tr:hover { background: #f9f9f9; }
        .btn { background: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin: 5px; }
        .btn-danger { background: #e74c3c; }
        .btn-success { background: #27ae60; }
        .form-modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); justify-content: center; align-items: center; }
        .form-content { background: white; padding: 30px; border-radius: 10px; width: 90%; max-width: 500px; max-height: 80vh; overflow-y: auto; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; color: #555; }
        .form-group input, .form-group select, .form-group textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        .close-btn { float: right; font-size: 24px; cursor: pointer; color: #777; }
        .sale-items { margin: 15px 0; }
        .sale-item { border: 1px solid #eee; padding: 10px; margin-bottom: 10px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="sidebar">
        <h2>📊 ERP Sistema</h2>
        <ul>
            <li><a href="#" onclick="showSection('dashboard')">🏠 Dashboard</a></li>
            <li><a href="#" onclick="showSection('users')">👥 Usuários</a></li>
            <li><a href="#" onclick="showSection('clients')">👥 Clientes</a></li>
            <li><a href="#" onclick="showSection('products')">📦 Produtos</a></li>
            <li><a href="#" onclick="showSection('sales')">💰 Vendas</a></li>
            <li><a href="#" onclick="showSection('financial')">💼 Financeiro</a></li>
            <li><a href="#" onclick="logout()">🚪 Sair</a></li>
        </ul>
    </div>
    
    <div class="content">
        <div class="header">
            <h1 id="sectionTitle">Dashboard</h1>
            <div class="user-info">
                <span id="userName"></span>
                <button onclick="logout()" class="logout-btn">Sair</button>
            </div>
        </div>
        
        <!-- Dashboard -->
        <div id="dashboard" class="module-section active-section">
            <div class="dashboard-cards">
                <div class="card">
                    <h3>Usuários</h3>
                    <div class="value" id="usersCount">0</div>
                </div>
                <div class="card">
                    <h3>Clientes</h3>
                    <div class="value" id="clientsCount">0</div>
                </div>
                <div class="card">
                    <h3>Produtos</h3>
                    <div class="value" id="productsCount">0</div>
                </div>
                <div class="card">
                    <h3>Vendas Hoje</h3>
                    <div class="value" id="salesCount">0</div>
                </div>
            </div>
            <h3>Últimas Vendas</h3>
            <div id="recentSales"></div>
        </div>
        
        <!-- Usuários -->
        <div id="users" class="module-section">
            <button onclick="showUserForm()" class="btn btn-success">Novo Usuário</button>
            <div id="usersList"></div>
        </div>
        
        <!-- Clientes -->
        <div id="clients" class="module-section">
            <button onclick="showClientForm()" class="btn btn-success">Novo Cliente</button>
            <div id="clientsList"></div>
        </div>
        
        <!-- Produtos -->
        <div id="products" class="module-section">
            <button onclick="showProductForm()" class="btn btn-success">Novo Produto</button>
            <div id="productsList"></div>
        </div>
        
        <!-- Vendas -->
        <div id="sales" class="module-section">
            <button onclick="showSaleForm()" class="btn btn-success">Nova Venda</button>
            <div id="salesList"></div>
        </div>
        
        <!-- Financeiro -->
        <div id="financial" class="module-section">
            <button onclick="showFinancialForm()" class="btn btn-success">Nova Movimentação</button>
            <div id="financialList"></div>
        </div>
    </div>
    
    <!-- Modal para formulários -->
    <div id="formModal" class="form-modal">
        <div class="form-content">
            <span class="close-btn" onclick="closeForm()">&times;</span>
            <div id="formContent"></div>
        </div>
    </div>
    
    <script>
        // Configurações globais
        const API_URL = '/api';
        let currentUser = JSON.parse(localStorage.getItem('user') || '{}');
        
        // Verifica autenticação
        if (!localStorage.getItem('token')) {
            window.location.href = '/login.html';
        }
        
        // Inicializa dashboard
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('userName').textContent = currentUser.name + ' (' + currentUser.role + ')';
            loadDashboardData();
        });
        
        // Funções de navegação
        function showSection(sectionId) {
            document.querySelectorAll('.module-section').forEach(s => s.classList.remove('active-section'));
            document.getElementById(sectionId).classList.add('active-section');
            document.getElementById('sectionTitle').textContent = 
                sectionId === 'dashboard' ? 'Dashboard' :
                sectionId === 'users' ? 'Usuários' :
                sectionId === 'clients' ? 'Clientes' :
                sectionId === 'products' ? 'Produtos' :
                sectionId === 'sales' ? 'Vendas' : 'Financeiro';
            
            if (sectionId === 'users') loadUsers();
            if (sectionId === 'clients') loadClients();
            if (sectionId === 'products') loadProducts();
            if (sectionId === 'sales') loadSales();
            if (sectionId === 'financial') loadFinancial();
        }
        
        function logout() {
            localStorage.clear();
            window.location.href = '/login.html';
        }
        
        // Funções da API
        async function apiRequest(endpoint, method = 'GET', data = null) {
            const token = localStorage.getItem('token');
            const options = {
                method,
                headers: {
                    'Authorization': 'Bearer ' + token,
                    'Content-Type': 'application/json'
                }
            };
            if (data) options.body = JSON.stringify(data);
            
            const response = await fetch(API_URL + endpoint, options);
            if (response.status === 401) logout();
            return response;
        }
        
        // Dashboard
        async function loadDashboardData() {
            try {
                const [usersRes, clientsRes, productsRes, salesRes] = await Promise.all([
                    apiRequest('/users'),
                    apiRequest('/clients'),
                    apiRequest('/products'),
                    apiRequest('/sales')
                ]);
                
                const users = await usersRes.json();
                const clients = await clientsRes.json();
                const products = await productsRes.json();
                const sales = await salesRes.json();
                
                document.getElementById('usersCount').textContent = users.length;
                document.getElementById('clientsCount').textContent = clients.length;
                document.getElementById('productsCount').textContent = products.length;
                document.getElementById('salesCount').textContent = sales.length;
                
                // Últimas vendas
                const recentSales = sales.slice(0, 5);
                let html = '<table><tr><th>ID</th><th>Cliente</th><th>Total</th><th>Data</th></tr>';
                recentSales.forEach(sale => {
                    html += \`<tr>
                        <td>\${sale.id}</td>
                        <td>\${sale.Client?.name || 'N/A'}</td>
                        <td>R$ \${parseFloat(sale.total).toFixed(2)}</td>
                        <td>\${new Date(sale.date).toLocaleDateString()}</td>
                    </tr>\`;
                });
                html += '</table>';
                document.getElementById('recentSales').innerHTML = html;
            } catch (error) {
                console.error('Erro ao carregar dashboard:', error);
            }
        }
        
        // Módulo de Usuários
        async function loadUsers() {
            try {
                const response = await apiRequest('/users');
                const users = await response.json();
                
                let html = '<table><tr><th>ID</th><th>Nome</th><th>E-mail</th><th>Perfil</th><th>Ações</th></tr>';
                users.forEach(user => {
                    html += \`<tr>
                        <td>\${user.id}</td>
                        <td>\${user.name}</td>
                        <td>\${user.email}</td>
                        <td>\${user.role}</td>
                        <td>
                            <button onclick="editUser(\${user.id})" class="btn">Editar</button>
                            <button onclick="deleteUser(\${user.id})" class="btn btn-danger">Excluir</button>
                        </td>
                    </tr>\`;
                });
                html += '</table>';
                document.getElementById('usersList').innerHTML = html;
            } catch (error) {
                console.error('Erro ao carregar usuários:', error);
            }
        }
        
        function showUserForm(user = null) {
            const isEdit = user !== null;
            document.getElementById('formContent').innerHTML = \`
                <h2>\${isEdit ? 'Editar' : 'Novo'} Usuário</h2>
                <form onsubmit="saveUser(event, \${isEdit ? user.id : 'null'})">
                    <div class="form-group">
                        <label>Nome:</label>
                        <input type="text" id="userName" value="\${isEdit ? user.name : ''}" required>
                    </div>
                    <div class="form-group">
                        <label>E-mail:</label>
                        <input type="email" id="userEmail" value="\${isEdit ? user.email : ''}" required>
                    </div>
                    <div class="form-group">
                        <label>Senha\${isEdit ? ' (deixe em branco para manter)' : ''}:</label>
                        <input type="password" id="userPassword" \${isEdit ? '' : 'required'}>
                    </div>
                    <div class="form-group">
                        <label>Perfil:</label>
                        <select id="userRole" required>
                            <option value="operador" \${isEdit && user.role === 'operador' ? 'selected' : ''}>Operador</option>
                            <option value="admin" \${isEdit && user.role === 'admin' ? 'selected' : ''}>Administrador</option>
                        </select>
                    </div>
                    <button type="submit" class="btn">Salvar</button>
                </form>
            \`;
            document.getElementById('formModal').style.display = 'flex';
        }
        
        async function saveUser(e, userId) {
            e.preventDefault();
            const userData = {
                name: document.getElementById('userName').value,
                email: document.getElementById('userEmail').value,
                role: document.getElementById('userRole').value
            };
            const password = document.getElementById('userPassword').value;
            if (password) userData.password = password;
            
            const endpoint = userId ? \`/users/\${userId}\` : '/users';
            const method = userId ? 'PUT' : 'POST';
            
            const response = await apiRequest(endpoint, method, userData);
            if (response.ok) {
                alert('Usuário salvo com sucesso!');
                closeForm();
                loadUsers();
            }
        }
        
        async function editUser(id) {
            const response = await apiRequest(\`/users/\${id}\`);
            const user = await response.json();
            showUserForm(user);
        }
        
        async function deleteUser(id) {
            if (!confirm('Tem certeza que deseja excluir este usuário?')) return;
            const response = await apiRequest(\`/users/\${id}\`, 'DELETE');
            if (response.ok) {
                alert('Usuário excluído com sucesso!');
                loadUsers();
            }
        }
        
        // Módulo de Clientes (similar ao de usuários)
        async function loadClients() {
            try {
                const response = await apiRequest('/clients');
                const clients = await response.json();
                
                let html = '<table><tr><th>ID</th><th>Nome</th><th>E-mail</th><th>Telefone</th><th>Endereço</th><th>Ações</th></tr>';
                clients.forEach(client => {
                    html += \`<tr>
                        <td>\${client.id}</td>
                        <td>\${client.name}</td>
                        <td>\${client.email}</td>
                        <td>\${client.phone}</td>
                        <td>\${client.address}</td>
                        <td>
                            <button onclick="editClient(\${client.id})" class="btn">Editar</button>
                            <button onclick="deleteClient(\${client.id})" class="btn btn-danger">Excluir</button>
                        </td>
                    </tr>\`;
                });
                html += '</table>';
                document.getElementById('clientsList').innerHTML = html;
            } catch (error) {
                console.error('Erro ao carregar clientes:', error);
            }
        }
        
        function showClientForm(client = null) {
            const isEdit = client !== null;
            document.getElementById('formContent').innerHTML = \`
                <h2>\${isEdit ? 'Editar' : 'Novo'} Cliente</h2>
                <form onsubmit="saveClient(event, \${isEdit ? client.id : 'null'})">
                    <div class="form-group">
                        <label>Nome:</label>
                        <input type="text" id="clientName" value="\${isEdit ? client.name : ''}" required>
                    </div>
                    <div class="form-group">
                        <label>E-mail:</label>
                        <input type="email" id="clientEmail" value="\${isEdit ? client.email : ''}" required>
                    </div>
                    <div class="form-group">
                        <label>Telefone:</label>
                        <input type="text" id="clientPhone" value="\${isEdit ? client.phone : ''}" required>
                    </div>
                    <div class="form-group">
                        <label>Endereço:</label>
                        <input type="text" id="clientAddress" value="\${isEdit ? client.address : ''}" required>
                    </div>
                    <button type="submit" class="btn">Salvar</button>
                </form>
            \`;
            document.getElementById('formModal').style.display = 'flex';
        }
        
        async function saveClient(e, clientId) {
            e.preventDefault();
            const clientData = {
                name: document.getElementById('clientName').value,
                email: document.getElementById('clientEmail').value,
                phone: document.getElementById('clientPhone').value,
                address: document.getElementById('clientAddress').value
            };
            
            const endpoint = clientId ? \`/clients/\${clientId}\` : '/clients';
            const method = clientId ? 'PUT' : 'POST';
            
            const response = await apiRequest(endpoint, method, clientData);
            if (response.ok) {
                alert('Cliente salvo com sucesso!');
                closeForm();
                loadClients();
            }
        }
        
        async function editClient(id) {
            const response = await apiRequest(\`/clients/\${id}\`);
            const client = await response.json();
            showClientForm(client);
        }
        
        async function deleteClient(id) {
            if (!confirm('Tem certeza que deseja excluir este cliente?')) return;
            const response = await apiRequest(\`/clients/\${id}\`, 'DELETE');
            if (response.ok) {
                alert('Cliente excluído com sucesso!');
                loadClients();
            }
        }
        
        // Módulo de Produtos
        async function loadProducts() {
            try {
                const response = await apiRequest('/products');
                const products = await response.json();
                
                let html = '<table><tr><th>ID</th><th>Nome</th><th>Descrição</th><th>Preço</th><th>Estoque</th><th>Ações</th></tr>';
                products.forEach(product => {
                    html += \`<tr>
                        <td>\${product.id}</td>
                        <td>\${product.name}</td>
                        <td>\${product.description || ''}</td>
                        <td>R$ \${parseFloat(product.price).toFixed(2)}</td>
                        <td>\${product.stock}</td>
                        <td>
                            <button onclick="editProduct(\${product.id})" class="btn">Editar</button>
                            <button onclick="deleteProduct(\${product.id})" class="btn btn-danger">Excluir</button>
                        </td>
                    </tr>\`;
                });
                html += '</table>';
                document.getElementById('productsList').innerHTML = html;
            } catch (error) {
                console.error('Erro ao carregar produtos:', error);
            }
        }
        
        function showProductForm(product = null) {
            const isEdit = product !== null;
            document.getElementById('formContent').innerHTML = \`
                <h2>\${isEdit ? 'Editar' : 'Novo'} Produto</h2>
                <form onsubmit="saveProduct(event, \${isEdit ? product.id : 'null'})">
                    <div class="form-group">
                        <label>Nome:</label>
                        <input type="text" id="productName" value="\${isEdit ? product.name : ''}" required>
                    </div>
                    <div class="form-group">
                        <label>Descrição:</label>
                        <textarea id="productDescription">\${isEdit ? product.description || '' : ''}</textarea>
                    </div>
                    <div class="form-group">
                        <label>Preço:</label>
                        <input type="number" step="0.01" id="productPrice" value="\${isEdit ? product.price : ''}" required>
                    </div>
                    <div class="form-group">
                        <label>Estoque:</label>
                        <input type="number" id="productStock" value="\${isEdit ? product.stock : '0'}" required>
                    </div>
                    <button type="submit" class="btn">Salvar</button>
                </form>
            \`;
            document.getElementById('formModal').style.display = 'flex';
        }
        
        async function saveProduct(e, productId) {
            e.preventDefault();
            const productData = {
                name: document.getElementById('productName').value,
                description: document.getElementById('productDescription').value,
                price: parseFloat(document.getElementById('productPrice').value),
                stock: parseInt(document.getElementById('productStock').value)
            };
            
            const endpoint = productId ? \`/products/\${productId}\` : '/products';
            const method = productId ? 'PUT' : 'POST';
            
            const response = await apiRequest(endpoint, method, productData);
            if (response.ok) {
                alert('Produto salvo com sucesso!');
                closeForm();
                loadProducts();
            }
        }
        
        async function editProduct(id) {
            const response = await apiRequest(\`/products/\${id}\`);
            const product = await response.json();
            showProductForm(product);
        }
        
        async function deleteProduct(id) {
            if (!confirm('Tem certeza que deseja excluir este produto?')) return;
            const response = await apiRequest(\`/products/\${id}\`, 'DELETE');
            if (response.ok) {
                alert('Produto excluído com sucesso!');
                loadProducts();
            }
        }
        
        // Módulo de Vendas
        async function loadSales() {
            try {
                const response = await apiRequest('/sales');
                const sales = await response.json();
                
                let html = '<table><tr><th>ID</th><th>Cliente</th><th>Total</th><th>Data</th><th>Itens</th></tr>';
                sales.forEach(sale => {
                    html += \`<tr>
                        <td>\${sale.id}</td>
                        <td>\${sale.Client?.name || 'N/A'}</td>
                        <td>R$ \${parseFloat(sale.total).toFixed(2)}</td>
                        <td>\${new Date(sale.date).toLocaleDateString()}</td>
                        <td>\${sale.SaleItems?.length || 0} itens</td>
                    </tr>\`;
                });
                html += '</table>';
                document.getElementById('salesList').innerHTML = html;
            } catch (error) {
                console.error('Erro ao carregar vendas:', error);
            }
        }
        
        let saleItems = [];
        let clients = [];
        let products = [];
        
        async function showSaleForm() {
            // Carrega clientes e produtos
            const [clientsRes, productsRes] = await Promise.all([
                apiRequest('/clients'),
                apiRequest('/products')
            ]);
            clients = await clientsRes.json();
            products = await productsRes.json();
            
            saleItems = [];
            
            document.getElementById('formContent').innerHTML = \`
                <h2>Nova Venda</h2>
                <form onsubmit="saveSale(event)">
                    <div class="form-group">
                        <label>Cliente:</label>
                        <select id="saleClient" required>
                            <option value="">Selecione um cliente</option>
                            \${clients.map(c => \`<option value="\${c.id}">\${c.name}</option>\`).join('')}
                        </select>
                    </div>
                    
                    <h3>Itens da Venda</h3>
                    <div id="saleItemsContainer"></div>
                    <button type="button" onclick="addSaleItem()" class="btn">Adicionar Item</button>
                    
                    <div class="form-group">
                        <h4>Total: R$ <span id="saleTotal">0.00</span></h4>
                    </div>
                    
                    <button type="submit" class="btn btn-success">Registrar Venda</button>
                </form>
            \`;
            document.getElementById('formModal').style.display = 'flex';
            addSaleItem();
        }
        
        function addSaleItem() {
            const container = document.getElementById('saleItemsContainer');
            const itemId = saleItems.length;
            
            const itemDiv = document.createElement('div');
            itemDiv.className = 'sale-item';
            itemDiv.innerHTML = \`
                <div class="form-group">
                    <label>Produto:</label>
                    <select class="product-select" onchange="updateSaleItemPrice(\${itemId})" required>
                        <option value="">Selecione um produto</option>
                        \${products.map(p => \`<option value="\${p.id}" data-price="\${p.price}">\${p.name} (Estoque: \${p.stock})</option>\`).join('')}
                    </select>
                </div>
                <div class="form-group">
                    <label>Quantidade:</label>
                    <input type="number" class="quantity" min="1" value="1" onchange="calculateSaleTotal()" required>
                </div>
                <div class="form-group">
                    <label>Preço Unitário:</label>
                    <input type="number" class="price" step="0.01" onchange="calculateSaleTotal()" required>
                </div>
                <button type="button" onclick="removeSaleItem(\${itemId})" class="btn btn-danger">Remover</button>
            \`;
            
            container.appendChild(itemDiv);
            saleItems.push({ productId: null, quantity: 1, price: 0 });
        }
        
        function updateSaleItemPrice(index) {
            const select = document.querySelectorAll('.product-select')[index];
            const priceInput = document.querySelectorAll('.price')[index];
            const selectedOption = select.options[select.selectedIndex];
            const price = selectedOption.getAttribute('data-price');
            
            if (price) {
                priceInput.value = price;
                saleItems[index].price = parseFloat(price);
                saleItems[index].productId = parseInt(select.value);
                calculateSaleTotal();
            }
        }
        
        function removeSaleItem(index) {
            if (saleItems.length > 1) {
                saleItems.splice(index, 1);
                document.querySelectorAll('.sale-item')[index].remove();
                calculateSaleTotal();
            }
        }
        
        function calculateSaleTotal() {
            let total = 0;
            document.querySelectorAll('.sale-item').forEach((item, index) => {
                const quantity = parseFloat(item.querySelector('.quantity').value) || 0;
                const price = parseFloat(item.querySelector('.price').value) || 0;
                saleItems[index].quantity = quantity;
                saleItems[index].price = price;
                total += quantity * price;
            });
            document.getElementById('saleTotal').textContent = total.toFixed(2);
        }
        
        async function saveSale(e) {
            e.preventDefault();
            const clientId = document.getElementById('saleClient').value;
            
            // Valida itens
            const validItems = saleItems.filter(item => item.productId && item.quantity > 0 && item.price > 0);
            if (validItems.length === 0) {
                alert('Adicione pelo menos um item válido à venda');
                return;
            }
            
            const saleData = {
                clientId: parseInt(clientId),
                items: validItems
            };
            
            const response = await apiRequest('/sales', 'POST', saleData);
            if (response.ok) {
                alert('Venda registrada com sucesso!');
                closeForm();
                loadSales();
            }
        }
        
        // Módulo Financeiro
        async function loadFinancial() {
            try {
                const response = await apiRequest('/financial');
                const financials = await response.json();
                
                let totalEntradas = 0;
                let totalSaidas = 0;
                
                let html = '<table><tr><th>ID</th><th>Tipo</th><th>Valor</th><th>Descrição</th><th>Data</th><th>Ações</th></tr>';
                financials.forEach(f => {
                    const tipo = f.type === 'entrada' ? 'Entrada' : 'Saída';
                    const classe = f.type === 'entrada' ? 'income' : 'outcome';
                    
                    if (f.type === 'entrada') totalEntradas += parseFloat(f.amount);
                    else totalSaidas += parseFloat(f.amount);
                    
                    html += \`<tr>
                        <td>\${f.id}</td>
                        <td class="\${classe}">\${tipo}</td>
                        <td>R$ \${parseFloat(f.amount).toFixed(2)}</td>
                        <td>\${f.description}</td>
                        <td>\${new Date(f.date).toLocaleDateString()}</td>
                        <td>
                            <button onclick="editFinancial(\${f.id})" class="btn">Editar</button>
                            <button onclick="deleteFinancial(\${f.id})" class="btn btn-danger">Excluir</button>
                        </td>
                    </tr>\`;
                });
                html += '</table>';
                html += \`<div style="margin-top: 20px;">
                    <h3>Resumo</h3>
                    <p>Total Entradas: R$ \${totalEntradas.toFixed(2)}</p>
                    <p>Total Saídas: R$ \${totalSaidas.toFixed(2)}</p>
                    <p><strong>Saldo: R$ \${(totalEntradas - totalSaidas).toFixed(2)}</strong></p>
                </div>\`;
                document.getElementById('financialList').innerHTML = html;
            } catch (error) {
                console.error('Erro ao carregar financeiro:', error);
            }
        }
        
        function showFinancialForm(financial = null) {
            const isEdit = financial !== null;
            document.getElementById('formContent').innerHTML = \`
                <h2>\${isEdit ? 'Editar' : 'Nova'} Movimentação</h2>
                <form onsubmit="saveFinancial(event, \${isEdit ? financial.id : 'null'})">
                    <div class="form-group">
                        <label>Tipo:</label>
                        <select id="financialType" required>
                            <option value="entrada" \${isEdit && financial.type === 'entrada' ? 'selected' : ''}>Entrada</option>
                            <option value="saida" \${isEdit && financial.type === 'saida' ? 'selected' : ''}>Saída</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Valor:</label>
                        <input type="number" step="0.01" id="financialAmount" value="\${isEdit ? financial.amount : ''}" required>
                    </div>
                    <div class="form-group">
                        <label>Descrição:</label>
                        <input type="text" id="financialDescription" value="\${isEdit ? financial.description : ''}" required>
                    </div>
                    <button type="submit" class="btn">Salvar</button>
                </form>
            \`;
            document.getElementById('formModal').style.display = 'flex';
        }
        
        async function saveFinancial(e, financialId) {
            e.preventDefault();
            const financialData = {
                type: document.getElementById('financialType').value,
                amount: parseFloat(document.getElementById('financialAmount').value),
                description: document.getElementById('financialDescription').value
            };
            
            const endpoint = financialId ? \`/financial/\${financialId}\` : '/financial';
            const method = financialId ? 'PUT' : 'POST';
            
            const response = await apiRequest(endpoint, method, financialData);
            if (response.ok) {
                alert('Movimentação salva com sucesso!');
                closeForm();
                loadFinancial();
            }
        }
        
        async function editFinancial(id) {
            const response = await apiRequest(\`/financial/\${id}\`);
            const financial = await response.json();
            showFinancialForm(financial);
        }
        
        async function deleteFinancial(id) {
            if (!confirm('Tem certeza que deseja excluir esta movimentação?')) return;
            const response = await apiRequest(\`/financial/\${id}\`, 'DELETE');
            if (response.ok) {
                alert('Movimentação excluída com sucesso!');
                loadFinancial();
            }
        }
        
        // Funções gerais
        function closeForm() {
            document.getElementById('formModal').style.display = 'none';
        }
        
        // Fecha modal ao clicar fora
        window.onclick = function(event) {
            const modal = document.getElementById('formModal');
            if (event.target === modal) {
                closeForm();
            }
        };
    </script>
</body>
</html>
`);

// ======================
// PACOTE package.json
// ======================

fs.writeFileSync('package.json', JSON.stringify({
  "name": "erp-sistema-completo",
  "version": "1.0.0",
  "description": "Sistema ERP Full Stack completo",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "bcrypt": "^5.1.1",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.2",
    "sequelize": "^6.32.1",
    "sqlite3": "^5.1.6"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}, null, 2));

// ======================
// ARQUIVO .env
// ======================

fs.writeFileSync('.env', `
PORT=3000
JWT_SECRET=seu_segredo_super_seguro_do_erp_2024
NODE_ENV=development
`);

// ======================
// README.md
// ======================

fs.writeFileSync('README.md', `
# 🚀 SISTEMA ERP COMPLETO

Sistema ERP Full Stack completo com backend (Node.js/Express) e frontend (HTML/CSS/JS) em um único arquivo.

## 📋 Funcionalidades

✅ **Autenticação com JWT** - Login seguro com tokens  
✅ **Controle de Usuários** - CRUD completo com perfis (admin/operador)  
✅ **Gestão de Clientes** - Cadastro completo de clientes  
✅ **Controle de Produtos** - Cadastro com estoque e preços  
✅ **Sistema de Vendas** - Registro de vendas com baixa automática no estoque  
✅ **Controle Financeiro** - Entradas e saídas financeiras  
✅ **Dashboard** - Painel com estatísticas em tempo real  
✅ **Interface Responsiva** - Design moderno e responsivo  

## 🛠️ Tecnologias

- **Backend:** Node.js, Express, Sequelize (SQLite)
- **Autenticação:** JWT, bcrypt
- **Frontend:** HTML5, CSS3, JavaScript puro
- **Banco de Dados:** SQLite (em memória para fácil execução)

## 🚀 Como Executar

### 1. Instalação
\`\`\`bash
npm install
\`\`\`

### 2. Execução
\`\`\`bash
npm start
# ou para desenvolvimento
npm run dev
\`\`\`

### 3. Acessar
- Sistema: http://localhost:3000
- Login: http://localhost:3000/login.html
- Dashboard: http://localhost:3000/dashboard.html

## 👤 Credenciais Padrão

**Administrador:**
- E-mail: admin@erp.com
- Senha: admin123

## 📁 Estrutura do Código

O sistema está organizado em um único arquivo (\`server.js\`) que contém:

1. **Backend completo** com todas as APIs
2. **Frontend completo** com todas as interfaces
3. **Banco de dados SQLite** em memória
4. **Arquivos estáticos** gerados dinamicamente

## 🔧 Endpoints da API

- \`POST /api/auth/login\` - Login
- \`POST /api/auth/register\` - Registro
- \`GET /api/users\` - Listar usuários (admin)
- \`GET /api/clients\` - Listar clientes
- \`GET /api/products\` - Listar produtos
- \`POST /api/sales\` - Criar venda
- \`GET /api/financial\` - Listar financeiro (admin)

## 📊 Banco de Dados

O sistema usa SQLite em memória com as seguintes tabelas:
- \`users\` - Usuários do sistema
- \`clients\` - Clientes
- \`products\` - Produtos
- \`sales\` - Vendas
- \`sale_items\` - Itens das vendas
- \`financials\` - Movimentações financeiras

## 🎯 Funcionalidades Avançadas

1. **Controle de Permissões** - Admin vs Operador
2. **Baixa Automática de Estoque** - Ao registrar venda
3. **Registro Financeiro Automático** - Vendas geram entradas
4. **Dashboard em Tempo Real** - Estatísticas atualizadas
5. **Interface Intuitiva** - Navegação simplificada

## ⚠️ Notas Importantes

- O banco de dados é em memória (reinicia ao reiniciar o servidor)
- Para produção, configure um banco de dados persistente
- Use HTTPS em produção
- Configure variáveis de ambiente adequadas

## 📞 Suporte

Sistema desenvolvido como exemplo completo de ERP Full Stack.

---

**Desenvolvido com ❤️ para demonstração técnica**
`);

console.log(`
==========================================
✅ SISTEMA ERP COMPLETO CRIADO COM SUCESSO!
==========================================

📁 Arquivos criados:
- server.js (sistema completo)
- package.json (dependências)
- .env (variáveis de ambiente)
- README.md (documentação)

🚀 Para executar:
1. npm install
2. npm start
3. Acesse: http://localhost:3000

👤 Login padrão:
- Email: admin@erp.com
- Senha: admin123

==========================================
`);