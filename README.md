
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
```bash
npm install
```

### 2. Execução
```bash
npm start
# ou para desenvolvimento
npm run dev
```

### 3. Acessar
- Sistema: http://localhost:3000
- Login: http://localhost:3000/login.html
- Dashboard: http://localhost:3000/dashboard.html

## 👤 Credenciais Padrão

**Administrador:**
- E-mail: admin@erp.com
- Senha: admin123

## 📁 Estrutura do Código

O sistema está organizado em um único arquivo (`server.js`) que contém:

1. **Backend completo** com todas as APIs
2. **Frontend completo** com todas as interfaces
3. **Banco de dados SQLite** em memória
4. **Arquivos estáticos** gerados dinamicamente

## 🔧 Endpoints da API

- `POST /api/auth/login` - Login
- `POST /api/auth/register` - Registro
- `GET /api/users` - Listar usuários (admin)
- `GET /api/clients` - Listar clientes
- `GET /api/products` - Listar produtos
- `POST /api/sales` - Criar venda
- `GET /api/financial` - Listar financeiro (admin)

## 📊 Banco de Dados

O sistema usa SQLite em memória com as seguintes tabelas:
- `users` - Usuários do sistema
- `clients` - Clientes
- `products` - Produtos
- `sales` - Vendas
- `sale_items` - Itens das vendas
- `financials` - Movimentações financeiras

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
