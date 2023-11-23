import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import morgan from 'morgan';
import { pool } from './db.js';  // Asegúrate de que este archivo esté configurado correctamente
import { PORT, JWT_SECRET } from './config.js';

const app = express();

app.use(express.json());
app.use(cors());
app.use(morgan('dev'));

// Ruta para obtener todos los roles
app.get('/roles', async (req, res) => {
    try {
        const [results] = await pool.query('SELECT * FROM roles');
        res.json(results);
    } catch (err) {
        console.error('Error al obtener los roles:', err);
        res.status(500).json({ error: 'Error al obtener los roles' });
    }
});

// Ruta para obtener todos los usuarios
app.get('/usuarios', async (req, res) => {
    try {
        const [results] = await pool.query('SELECT * FROM usuarios');
        res.json(results);
    } catch (err) {
        console.error('Error al obtener los usuarios:', err);
        res.status(500).json({ error: 'Error al obtener los usuarios' });
    }
});

// Ruta para agregar un nuevo usuario
app.post('/addusuarios', async (req, res) => {
    const { nombre, apellidos, email, contrasena, direccion, rol_id, estatus } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(contrasena, 10);
        const query = 'INSERT INTO usuarios (nombre, apellidos, email, contrasena, direccion, rol_id, estatus) VALUES (?, ?, ?, ?, ?, ?, ?)';
        await pool.query(query, [nombre, apellidos, email, hashedPassword, direccion, rol_id, estatus]);
        res.json({ message: 'Usuario añadido correctamente' });
    } catch (err) {
        console.error('Error al añadir el usuario:', err);
        res.status(500).json({ error: 'Error al añadir el usuario' });
    }
});

// Ruta para eliminar un usuario
app.delete('/delusuario/:id', async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM usuarios WHERE id = ?', [id]);
        res.json({ message: 'Usuario eliminado correctamente' });
    } catch (err) {
        console.error('Error al eliminar el usuario:', err);
        res.status(500).json({ error: 'Error al eliminar el usuario' });
    }
});

// Ruta para modificar un usuario
app.put('/editusuario/:id', async (req, res) => {
    const { id } = req.params;
    const { nombre, apellidos, email, contrasena, direccion, rol_id, estatus } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(contrasena, 10);
        const query = 'UPDATE usuarios SET nombre = ?, apellidos = ?, email = ?, contrasena = ?, direccion = ?, rol_id = ?, estatus = ? WHERE id = ?';
        await pool.query(query, [nombre, apellidos, email, hashedPassword, direccion, rol_id, estatus, id]);
        res.json({ message: 'Información del usuario modificada correctamente' });
    } catch (err) {
        console.error('Error al modificar el usuario:', err);
        res.status(500).json({ error: 'Error al modificar el usuario' });
    }
});

// Ruta para registrar un nuevo usuario
app.post('/registrar', async (req, res) => {
    const { nombre, apellidos, email, contrasena } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(contrasena, 10);
        const query = 'INSERT INTO usuarios (nombre, apellidos, email, contrasena, rol_id, estatus) VALUES (?, ?, ?, ?, 2, 1)';
        await pool.query(query, [nombre, apellidos, email, hashedPassword]);
        res.json({ Estatus: 'CORRECTO' });
    } catch (err) {
        console.log('Error al registrar usuario:', err);
        res.status(500).json({ Estatus: 'ERROR', Error: 'Error al registrar usuario' });
    }
});

// Ruta para iniciar sesión
app.post('/login', async (req, res) => {
    const { email, contrasena } = req.body;
    try {
        const [resultados] = await pool.query('SELECT id, contrasena FROM usuarios WHERE email = ?', [email]);
        if (resultados.length === 0) {
            return res.json({ Error: 'Usuario no encontrado.' });
        }
        const usuario = resultados[0];
        const match = await bcrypt.compare(contrasena, usuario.contrasena);
        if (match) {
            const token = jwt.sign({ email: usuario.email, id: usuario.id }, JWT_SECRET);
            return res.json({ Estatus: 'CORRECTO', Resultado: usuario, token });
        } else {
            return res.json({ Error: 'Error en las credenciales del usuario' });
        }
    } catch (err) {
        return res.json({ Error: 'Error en la consulta.' });
    }
});
// Ruta para verificar correo
app.post('/VerificarCorreo', async (req, res) => {
    const { email } = req.body;
    try {
        const [resultados] = await pool.query('SELECT * FROM usuarios WHERE email = ?', [email]);
        if (resultados.length > 0) {
            res.json({ Estatus: "Correcto", Resultado: resultados });
        } else {
            res.json({ Error: "El usuario no existe" });
        }
    } catch (error) {
        res.json({ Error: "Error en la consulta" });
    }
});

// Middleware para autenticar usuario
const autenticarUsuario = (req, res, next) => {
    const tokenHeader = req.headers.authorization;
    if (!tokenHeader) {
        return res.status(401).json({ Error: "Acceso no autorizado" });
    }

    const token = tokenHeader.split(" ")[1]; // Asume formato "Bearer <token>"
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ Error: "Token inválido" });
    }
};

// Ruta para obtener el usuario actual
app.get('/UsuarioActual', autenticarUsuario, async (req, res) => {
    const { id } = req.user;
    try {
        const [resultados] = await pool.query('SELECT * FROM usuarios WHERE id = ?', [id]);
        if (resultados.length > 0) {
            const usuario = resultados[0];
            res.json({ Estatus: "CORRECTO", Resultado: usuario });
        } else {
            res.status(404).json({ Error: "Usuario no encontrado" });
        }
    } catch (error) {
        res.status(500).json({ Error: "Error en la consulta" });
    }
});

// Ruta para obtener platillos por categoría
app.get('/obtenerPlatillos/:categoria', async (req, res) => {
    const { categoria } = req.params;
    try {
        const [resultado] = await pool.query('SELECT * FROM platillos WHERE categoria = ?', [categoria]);
        res.json({ Estatus: "Exitoso", Resultado: resultado });
    } catch (error) {
        res.json({ Error: "Error en la consulta" });
    }
});

// Ruta para buscar platillos por nombre
app.get('/buscarPlatillos/:busqueda', async (req, res) => {
    const { busqueda } = req.params;
    try {
        const [resultado] = await pool.query('SELECT * FROM platillos WHERE nombre LIKE ?', [`%${busqueda}%`]);
        res.json({ Estatus: "Exitoso", Resultado: resultado });
    } catch (error) {
        res.json({ Error: "Error en la consulta" });
    }
});

// Ruta para agregar a favoritos
app.post('/agregarFavorito', async (req, res) => {
    const { usuario_id, platillo_id } = req.body;
    try {
        await pool.query('INSERT INTO favoritos_usuario (usuario_id, platillo_id) VALUES (?, ?)', [usuario_id, platillo_id]);
        res.json({ Estatus: "Exitoso", Resultado: "Favorito agregado" });
    } catch (error) {
        res.json({ Error: "Error al agregar a favoritos" });
    }
});

// Ruta para quitar de favoritos
app.delete('/favoritos', async (req, res) => {
    const { usuario_id, platillo_id } = req.body;
    try {
        await pool.query('DELETE FROM favoritos_usuario WHERE usuario_id = ? AND platillo_id = ?', [usuario_id, platillo_id]);
        res.json({ message: 'Eliminado de favoritos correctamente' });
    } catch (err) {
        console.error('Error al quitar de favoritos:', err);
        res.status(500).json({ error: 'Error al quitar de favoritos' });
    }
});

// Ruta para obtener favoritos
app.get('/obtenerFavoritos/:usuario_id', async (req, res) => {
    const { usuario_id } = req.params;
    try {
        const [resultado] = await pool.query(`
            SELECT p.* FROM platillos p
            INNER JOIN favoritos_usuario f ON p.id = f.platillo_id
            WHERE f.usuario_id = ?`, [usuario_id]);
        res.json({ Estatus: "Exitoso", Resultado: resultado });
    } catch (error) {
        res.json({ Error: "Error al obtener favoritos" });
    }
});

// Ruta para obtener todos los platillos
app.get('/platillos', async (req, res) => {
    try {
        const [results] = await pool.query('SELECT * FROM platillos');
        res.json(results);
    } catch (err) {
        console.error('Error al obtener los platillos:', err);
        res.status(500).json({ error: 'Error al obtener los platillos' });
    }
});


// Iniciar server

app.listen(PORT, () => {
  console.log(`Servidor iniciado en el puerto ${PORT}`);
});