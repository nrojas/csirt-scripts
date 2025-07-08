`get-ioc.py`

Este script sirve para **recuperar los indicadores de compromiso del CSIRT nacional** usando la API que han expuesto.

Para acceder a esta API primero hay que realizar el proceso de registro detallado en las condiciones e instrucciones para intercambio de Indicadores de Compromiso:
[https://csirt.gob.cl/servicios/intercambio-de-indicadores-de-compromiso/](https://csirt.gob.cl/servicios/intercambio-de-indicadores-de-compromiso/)

El script creará un directorio en la ubicación donde se ejecuta llamado "**Resultados**". En este directorio se irán almacenando los *distintos IOCs* que se encuentren en la ventana de tiempo que se defina.

En la versión preliminar se ha considerado sólo realizar una recopilación del **día actual (00:00 - 23:59:59)**.

Los tokens de acceso deben ser almacenado en un archivo `.env`:

`API_USER="usuario@dominio.cl"`

`API_PASS="contraseña-de-acceso-api"`

Se deben conservar las comillas para que sea *interpretado correctamente* durante la llamada.

