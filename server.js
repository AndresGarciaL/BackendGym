import express from 'express';
import mysql from 'mysql';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import morgan from 'morgan';
import multer from 'multer';

const app = express();
app.use(express.json());
app.use(cors());
app.use(morgan('dev'));

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'monsteri_gym',
});

connection.connect((error) => {
  if (error) {
    console.log('No fue posible la conexión');
  } else {
    console.log('Conexión con el servidor exitosa');
  }
});

const storage = multer.diskStorage({
  destination: '../frontend/src/images/Productos', // Change the destination folder to your desired location
  filename: function (req, file, cb) {
    // Get the original file extension
    const originalFileExtension = file.originalname.split('').pop();
    cb(null, file.originalname); // Use the original file name as the new filename
  },
});

const upload = multer({ storage: storage });

// Ruta para añadir un nuevo producto with image upload
app.post('/addproducto', upload.single('image'), (req, res) => {
  const { nombre, descripcion, precio, stock, categoria } = req.body;
  const image = req.file.filename; // Save the filename in the database

  const query = `INSERT INTO productos (nombre, descripcion, precio, stock, categoria_id, image) VALUES (?, ?, ?, ?, ?, ?)`;
  const values = [nombre, descripcion, precio, stock, categoria, image];

  connection.query(query, values, (err, results) => {
    if (err) {
      console.error('Error al añadir el producto:', err);
      res.status(500).json({ error: 'Error al añadir el producto' });
      return;
    }

    res.json({ message: 'Producto añadido correctamente' });
  });
});

//Ruta para obtener todos los roles
// Ruta para obtener todos los roles
app.get('/roles', (req, res) => {
  const query = 'SELECT * FROM roles';

  connection.query(query, (err, results) => {
    if (err) {
      console.error('Error al obtener los roles:', err);
      res.status(500).json({ error: 'Error al obtener los roles' });
      return;
    }

    res.json(results);
  });
});


// Ruta para obtener todos los usuarios
app.get('/usuarios', (req, res) => {
  const query = 'SELECT * FROM usuarios';

  connection.query(query, (err, results) => {
    if (err) {
      console.error('Error al obtener los usuarios:', err);
      res.status(500).json({ error: 'Error al obtener los usuarios' });
      return;
    }

    res.json(results);
  });
});

//RUTA PARA AGREGAR UN NUEVO USUARIO
app.post('/addusuarios', (req, res) => {
  const { nombre, apellidos, email, contrasena, direccion, rol_id, estatus } = req.body;

  // Generar el hash de la contraseña
  bcrypt.hash(contrasena, 10, (error, hash) => {
    if (error) {
      console.error('Error al generar el hash de la contraseña:', error);
      res.status(500).json({ error: 'Error al añadir el usuario' });
      return;
    }

    // El hash se encuentra en la variable 'hash', ahora podemos usarlo en la consulta
    const query = `INSERT INTO usuarios (nombre, apellidos, email, contrasena, direccion, rol_id, estatus) VALUES (?, ?, ?, ?, ?, ?, 1)`;
    const values = [nombre, apellidos, email, hash, direccion, rol_id, estatus];

    connection.query(query, values, (err, results) => {
      if (err) {
        console.error('Error al añadir el usuario:', err);
        res.status(500).json({ error: 'Error al añadir el usuario' });
        return;
      }

      res.json({ message: 'Usuario añadido correctamente' });
    });
  });
});

//RUTA PARA ELIMINAR UN USUARIO
app.delete('/delusuario/:id', (req, res) => {
  const id = req.params.id;
  const query = `DELETE FROM usuarios WHERE id = ?`;

  connection.query(query, [id], (err, results) => {
    if (err) {
      console.error('Error al eliminar el usuario:', err);
      res.status(500).json({ error: 'Error al eliminar el usuario' });
      return;
    }

    res.json({ message: 'Usuario eliminado correctamente' });
  });
});


//RUTA PARA MODIFICAR UN USUARIO
app.put('/editusuario/:id', (req, res) => {
  const id = req.params.id;
  const { nombre, apellidos, email, contrasena, direccion, rol_id, estatus } = req.body;
  const query = `UPDATE usuarios SET nombre = ?, apellidos = ?, email = ?, contrasena = ?, direccion = ?, rol_id = ?, estatus = ? WHERE id = ?`;
  const values = [nombre, apellidos, email, contrasena, direccion, rol_id, estatus, id];

  connection.query(query, values, (err, results) => {
    if (err) {
      console.error('Error al modificar el usuario:', err);
      res.status(500).json({ error: 'Error al modificar el usuario' });
      return;
    }

    res.json({ message: 'Información del usuario modificada correctamente' });
  });
});

// Register
app.post('/registrar', (req, res) => {
  const { nombre,apellidos, email, contrasena } = req.body;

  // Generar el hash de la contraseña
  bcrypt.hash(contrasena, 10, (error, hash) => {
    if (error) {
      console.log('Error al generar el hash de la contraseña', error);
      res.status(500).json({ Estatus: 'ERROR', Error: 'Error al registrar usuario' });
    } else {
      const sql = 'INSERT INTO usuarios (nombre,apellidos, email, contrasena,rol_id, estatus) VALUES (?,?,?,?,2,1)';
      connection.query(sql, [nombre,apellidos, email, hash], (error, resultado) => {
        if (error) {
          console.log('Error al registrar usuario', error);
          res.status(500).json({ Estatus: 'ERROR', Error: 'Error al registrar usuario' });
        } else {
          res.json({ Estatus: 'CORRECTO' });
        }
      });
    }
  });
});

app.post("/login", (peticion, respuesta) => {
  const { email, contrasena } = peticion.body;

  // Cambia la consulta para obtener también el ID del usuario
  const query = "SELECT id, contrasena FROM usuarios WHERE email = ?";
  connection.query(query, [email], (error, resultados) => {
    if (error) return respuesta.json({ Error: "Error en la consulta." });
    if (resultados.length === 0) return respuesta.json({ Error: "Usuario no encontrado." });

    const usuario = resultados[0];
    const match = bcrypt.compareSync(contrasena, usuario.contrasena);

    if (match) {
      // Incluye tanto el email como el id en el token
      const token = jwt.sign({ email: usuario.email, id: usuario.id }, "secreto"); // Asegúrate de que 'secreto' sea una clave segura en producción
      return respuesta.json({ Estatus: "CORRECTO", Resultado: usuario, token });
    } else {
      return respuesta.json({ Error: "Error en las credenciales del usuario" });
    }
  });
});
  
  app.post("/VerificarCorreo", (peticion, respuesta) => {
    const { email } = peticion.body;
    const query = "SELECT * FROM usuarios WHERE email = ?";
    connection.query(query, [email], (error, resultados) => {
      if (error) {
        return respuesta.json({ Error: "Error en la consulta" });
      } else {
        if (resultados.length > 0) {
          return respuesta.json({ Estatus: "Correcto", Resultado: resultados });
        } else {
          return respuesta.json({ Error: "El usuario no existe" });
        }
      }
    });
  });
  
// Middleware para autenticar
const autenticarUsuario = (peticion, respuesta, siguiente) => {
  const tokenHeader = peticion.headers.authorization;
  if (!tokenHeader) {
    return respuesta.status(401).json({ Error: "Acceso no autorizado" });
  }

  const token = tokenHeader.split(" ")[1]; // Asume formato "Bearer <token>"
  try {
    const decoded = jwt.verify(token, "secreto");
    peticion.user = decoded;
    siguiente();
  } catch (error) {
    return respuesta.status(401).json({ Error: "Token inválido" });
  }
};

// Ruta para obtener el usuario actual
app.get("/UsuarioActual", autenticarUsuario, (peticion, respuesta) => {
  const { id } = peticion.user;
  const query = "SELECT * FROM usuarios WHERE id = ?";
  connection.query(query, [id], (error, resultados) => {
    if (error) {
      return respuesta.status(500).json({ Error: "Error en la consulta" });
    } else {
      if (resultados.length > 0) {
        const usuario = resultados[0];
        return respuesta.json({ Estatus: "CORRECTO", Resultado: usuario });
      } else {
        return respuesta.status(404).json({ Error: "Usuario no encontrado" });
      }
    }
  });
});


// Ruta para obtener los platillos por categoría
app.get('/obtenerPlatillos/:categoria', (peticion, respuesta) => {
  const categoria = peticion.params.categoria;
  // Ajuste de la consulta SQL para buscar por categoría
  const sql = "SELECT * FROM platillos WHERE categoria = ?";
  // Envío a la conexión
  connection.query(sql, [categoria], (error, resultado) => {
      // Comprobación del resultado
      if (error) return respuesta.json({ Error: "Error en la consulta" });
      return respuesta.json({ Estatus: "Exitoso", Resultado: resultado });
  });
});

// Ruta para buscar platillos por nombre
app.get('/buscarPlatillos/:busqueda', (peticion, respuesta) => {
  const busqueda = peticion.params.busqueda;
  const sql = "SELECT * FROM platillos WHERE nombre LIKE ?";
  connection.query(sql, [`%${busqueda}%`], (error, resultado) => {
    if (error) return respuesta.json({ Error: "Error en la consulta" });
    return respuesta.json({ Estatus: "Exitoso", Resultado: resultado });
  });
});

//Agregar favoritos
app.post('/agregarFavorito', (peticion, respuesta) => {
  const { usuario_id, platillo_id } = peticion.body;

  const sql = 'INSERT INTO favoritos_usuario (usuario_id, platillo_id) VALUES (?, ?)';
  connection.query(sql, [usuario_id, platillo_id], (error, resultado) => {
    if (error) return respuesta.json({ Error: "Error al agregar a favoritos" });
    return respuesta.json({ Estatus: "Exitoso", Resultado: resultado });
  });
});


//Quitar favoritos

app.delete('/favoritos', (req, res) => {
  const { usuario_id, platillo_id } = req.body;
  const query = 'DELETE FROM favoritos_usuario WHERE usuario_id = ? AND platillo_id = ?';

  connection.query(query, [usuario_id, platillo_id], (err, results) => {
    if (err) {
      console.error('Error al quitar de favoritos:', err);
      res.status(500).json({ error: 'Error al quitar de favoritos' });
      return;
    }

    res.json({ message: 'Eliminado de favoritos correctamente' });
  });
});

//Obtener Favoritos

app.get('/obtenerFavoritos/:usuario_id', (peticion, respuesta) => {
  const usuario_id = peticion.params.usuario_id;

  const sql = `
    SELECT p.* FROM platillos p
    INNER JOIN favoritos_usuario f ON p.id = f.platillo_id
    WHERE f.usuario_id = ?;
  `;
  connection.query(sql, [usuario_id], (error, resultado) => {
    if (error) return respuesta.json({ Error: "Error al obtener favoritos" });
    return respuesta.json({ Estatus: "Exitoso", Resultado: resultado });
  });
});


//obtener platillos

app.get('/platillos', (req, res) => {
  const query = 'SELECT * FROM platillos'; // Consulta para obtener todos los platillos

  connection.query(query, (err, results) => {
    if (err) {
      console.error('Error al obtener los platillos:', err);
      res.status(500).json({ error: 'Error al obtener los platillos' });
      return;
    }

    res.json(results);
  });
});

// Iniciar server
const PORT = 8081;
app.listen(PORT, () => {
  console.log(`Servidor iniciado en el puerto ${PORT}`);
});