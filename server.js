const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Base de datos SQLite
const db = new Database('database.sqlite');

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

/* =========================================================
   INICIALIZACIÓN DE TABLAS SQLITE
========================================================= */
db.exec(`
  CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    nombre TEXT NOT NULL,
    rol TEXT NOT NULL CHECK(rol IN ('Administrador', 'Colaborador')),
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS cotizaciones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    email TEXT NOT NULL,
    telefono TEXT NOT NULL,
    empresa TEXT,
    servicio TEXT,
    mensaje TEXT NOT NULL,
    estado TEXT DEFAULT 'Nueva cotizacion' CHECK(estado IN ('Nueva cotizacion', 'Cotizacion respondida', 'Cotizacion rechazada', 'Cotizacion Aceptada')),
    en_papelera INTEGER DEFAULT 0,
    fecha_eliminacion DATETIME,
    creado_en DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Crear usuario Administrador inicial por defecto
const adminExists = db.prepare('SELECT id FROM usuarios WHERE usuario = ?').get('Admin');
if (!adminExists) {
  const hash = bcrypt.hashSync('Admin123@', 10);
  db.prepare('INSERT INTO usuarios (usuario, password, nombre, rol) VALUES (?, ?, ?, ?)').run(
    'Admin',
    hash,
    'Administrador Principal',
    'Administrador'
  );
  console.log('✅ Usuario Administrador inicial creado (Admin / Admin123@)');
}

// Tarea de limpieza automática de papelera (60 días)
function purgarPapelera() {
  try {
    const info = db.prepare(`
      DELETE FROM cotizaciones 
      WHERE en_papelera = 1 
      AND fecha_eliminacion <= datetime('now', '-60 days')
    `).run();
    if (info.changes > 0) {
      console.log(`[Auto-Purga] Se eliminaron permanentemente ${info.changes} cotizaciones con más de 60 días en papelera.`);
    }
  } catch (err) {
    console.error('Error al purgar papelera:', err);
  }
}
setInterval(purgarPapelera, 1000 * 60 * 60 * 12); // Ejecutar cada 12 horas
purgarPapelera();

/* =========================================================
   SESIONES SIMPLES EN MEMORIA
========================================================= */
const sesiones = new Map();

function authMiddleware(req, res, next) {
  const token = req.headers['x-auth-token'];
  if (!token || !sesiones.has(token)) {
    return res.status(401).json({ error: 'No autorizado. Inicie sesión nuevamente.' });
  }
  req.user = sesiones.get(token);
  next();
}

function adminOnly(req, res, next) {
  if (req.user.rol !== 'Administrador') {
    return res.status(403).json({ error: 'Acceso denegado: Requiere rol de Administrador.' });
  }
  next();
}

/* =========================================================
   RUTAS DE AUTENTICACIÓN
========================================================= */
app.post('/api/login', (req, res) => {
  const { usuario, password } = req.body;
  if (!usuario || !password) return res.status(400).json({ error: 'Campos requeridos faltantes.' });

  const user = db.prepare('SELECT * FROM usuarios WHERE usuario = ?').get(usuario.trim());
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
  }

  const token = 'token_' + Math.random().toString(36).substr(2) + Date.now().toString(36);
  const userData = { id: user.id, usuario: user.usuario, nombre: user.nombre, rol: user.rol };
  sesiones.set(token, userData);

  res.json({ message: 'Login exitoso', token, user: userData });
});

app.post('/api/logout', (req, res) => {
  const token = req.headers['x-auth-token'];
  if (token) sesiones.delete(token);
  res.json({ message: 'Sesión cerrada correctamente' });
});

// Perfil y cambio de contraseña/usuario (Para Admin y Colaborador)
app.put('/api/perfil', authMiddleware, (req, res) => {
  const { nuevoUsuario, nuevoNombre, passwordActual, nuevoPassword } = req.body;
  const user = db.prepare('SELECT * FROM usuarios WHERE id = ?').get(req.user.id);

  if (!user || !bcrypt.compareSync(passwordActual, user.password)) {
    return res.status(400).json({ error: 'La contraseña actual es incorrecta.' });
  }

  let finalPassword = user.password;
  if (nuevoPassword && nuevoPassword.trim().length >= 6) {
    finalPassword = bcrypt.hashSync(nuevoPassword.trim(), 10);
  }

  const finalUser = (nuevoUsuario && nuevoUsuario.trim()) || user.usuario;
  const finalNom = (nuevoNombre && nuevoNombre.trim()) || user.nombre;

  // Verificar si el usuario ya existe en otro registro
  const existeOtro = db.prepare('SELECT id FROM usuarios WHERE usuario = ? AND id != ?').get(finalUser, req.user.id);
  if (existeOtro) {
    return res.status(400).json({ error: 'El nombre de usuario ya está en uso.' });
  }

  db.prepare('UPDATE usuarios SET usuario = ?, nombre = ?, password = ? WHERE id = ?')
    .run(finalUser, finalNom, finalPassword, req.user.id);

  // Actualizar sesión
  req.user.usuario = finalUser;
  req.user.nombre = finalNom;
  sesiones.set(req.headers['x-auth-token'], req.user);

  res.json({ message: 'Perfil actualizado exitosamente.', user: req.user });
});

/* =========================================================
   GESTIÓN DE USUARIOS (SOLO ADMINISTRADOR)
========================================================= */
app.get('/api/usuarios', authMiddleware, adminOnly, (req, res) => {
  const users = db.prepare('SELECT id, usuario, nombre, rol, creado_en FROM usuarios ORDER BY id DESC').all();
  res.json(users);
});

app.post('/api/usuarios', authMiddleware, adminOnly, (req, res) => {
  const { usuario, password, nombre, rol } = req.body;
  if (!usuario || !password || !nombre || !rol) {
    return res.status(400).json({ error: 'Todos los campos son obligatorios.' });
  }
  if (!['Administrador', 'Colaborador'].includes(rol)) {
    return res.status(400).json({ error: 'Rol inválido.' });
  }

  const existe = db.prepare('SELECT id FROM usuarios WHERE usuario = ?').get(usuario.trim());
  if (existe) {
    return res.status(400).json({ error: 'El nombre de usuario ya existe.' });
  }

  const hash = bcrypt.hashSync(password.trim(), 10);
  const info = db.prepare('INSERT INTO usuarios (usuario, password, nombre, rol) VALUES (?, ?, ?, ?)')
    .run(usuario.trim(), hash, nombre.trim(), rol);

  res.json({ message: 'Usuario creado exitosamente', id: info.lastInsertRowid });
});

app.delete('/api/usuarios/:id', authMiddleware, adminOnly, (req, res) => {
  const userId = parseInt(req.params.id);
  if (userId === req.user.id) {
    return res.status(400).json({ error: 'No puedes eliminar tu propia cuenta.' });
  }
  db.prepare('DELETE FROM usuarios WHERE id = ?').run(userId);
  res.json({ message: 'Usuario eliminado correctamente.' });
});

/* =========================================================
   COTIZACIONES (PÚBLICO Y ADMIN/COLABORADOR)
========================================================= */
// Guardar cotización desde contacto.html
app.post('/api/cotizaciones', (req, res) => {
  const { nombre, email, telefono, empresa, servicio, mensaje } = req.body;

  if (!nombre || !email || !telefono || !mensaje) {
    return res.status(400).json({ error: 'Por favor complete todos los campos obligatorios.' });
  }

  try {
    const stmt = db.prepare(`
      INSERT INTO cotizaciones (nombre, email, telefono, empresa, servicio, mensaje)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    const info = stmt.run(nombre.trim(), email.trim(), telefono.trim(), (empresa || '').trim(), servicio || 'No especificado', mensaje.trim());
    res.json({ success: true, message: '¡Solicitud enviada correctamente!', id: info.lastInsertRowid });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al registrar la cotización en el servidor.' });
  }
});

// Listar cotizaciones activas
app.get('/api/cotizaciones', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT * FROM cotizaciones WHERE en_papelera = 0 ORDER BY creado_en DESC').all();
  res.json(rows);
});

// Listar papelera
app.get('/api/papelera', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT * FROM cotizaciones WHERE en_papelera = 1 ORDER BY fecha_eliminacion DESC').all();
  res.json(rows);
});

// Cambiar etiqueta/estado (Admin y Colaborador)
app.patch('/api/cotizaciones/:id/estado', authMiddleware, (req, res) => {
  const { estado } = req.body;
  const validos = ['Nueva cotizacion', 'Cotizacion respondida', 'Cotizacion rechazada', 'Cotizacion Aceptada'];
  if (!validos.includes(estado)) {
    return res.status(400).json({ error: 'Estado o etiqueta inválida.' });
  }
  db.prepare('UPDATE cotizaciones SET estado = ? WHERE id = ?').run(estado, req.params.id);
  res.json({ message: 'Estado actualizado correctamente.' });
});

// Mover a papelera (Admin y Colaborador)
app.patch('/api/cotizaciones/:id/papelera', authMiddleware, (req, res) => {
  db.prepare(`
    UPDATE cotizaciones 
    SET en_papelera = 1, fecha_eliminacion = datetime('now') 
    WHERE id = ?
  `).run(req.params.id);
  res.json({ message: 'Cotización movida a la papelera.' });
});

// Restaurar de papelera
app.patch('/api/cotizaciones/:id/restaurar', authMiddleware, (req, res) => {
  db.prepare(`
    UPDATE cotizaciones 
    SET en_papelera = 0, fecha_eliminacion = NULL 
    WHERE id = ?
  `).run(req.params.id);
  res.json({ message: 'Cotización restaurada con éxito.' });
});

// Eliminar permanentemente (Solo Administrador)
app.delete('/api/cotizaciones/:id', authMiddleware, adminOnly, (req, res) => {
  db.prepare('DELETE FROM cotizaciones WHERE id = ?').run(req.params.id);
  res.json({ message: 'Cotización eliminada definitivamente.' });
});

app.listen(PORT, () => {
  console.log(`🚀 Servidor ejecutándose en puerto ${PORT}`);
});