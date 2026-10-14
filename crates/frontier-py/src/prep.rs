// SPDX-License-Identifier: Apache-2.0
//! `frontier_native.prep`: thin numpy bindings over `frontier-prep-kernels`. Every function
//! takes C-contiguous arrays of the stated dtype (the Python wrappers in
//! `frontier_prep.kernels` convert), releases the GIL while the kernel runs and returns new
//! arrays. Malformed input raises `ValueError`.

use frontier_prep_kernels as kernels;
use numpy::{
    IntoPyArray, PyArray1, PyArray2, PyArrayDyn, PyArrayMethods, PyReadonlyArray1,
    PyReadonlyArray2, PyReadonlyArrayDyn, PyUntypedArrayMethods,
};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;

fn value_err(e: impl std::fmt::Display) -> PyErr {
    PyValueError::new_err(e.to_string())
}

/// `(M, 3)` faces as a flat slice.
fn faces_slice<'a>(faces: &'a PyReadonlyArray2<'_, i64>) -> PyResult<&'a [i64]> {
    if faces.shape()[1] != 3 {
        return Err(PyValueError::new_err(format!(
            "faces must be (M, 3), got {:?}",
            faces.shape()
        )));
    }
    faces
        .as_slice()
        .map_err(|_| PyValueError::new_err("faces must be C-contiguous"))
}

/// `(N, 3)` points of either float dtype.
enum Points<'py> {
    F32(PyReadonlyArray2<'py, f32>),
    F64(PyReadonlyArray2<'py, f64>),
}

impl<'py> Points<'py> {
    fn extract(obj: &Bound<'py, PyAny>) -> PyResult<Self> {
        let p = if let Ok(a) = obj.cast::<PyArray2<f32>>() {
            Self::F32(a.try_readonly().map_err(value_err)?)
        } else if let Ok(a) = obj.cast::<PyArray2<f64>>() {
            Self::F64(a.try_readonly().map_err(value_err)?)
        } else {
            return Err(PyTypeError::new_err(
                "points must be a 2-D float32 or float64 numpy array",
            ));
        };
        let shape = match &p {
            Self::F32(a) => a.shape().to_vec(),
            Self::F64(a) => a.shape().to_vec(),
        };
        if shape[1] != 3 {
            return Err(PyValueError::new_err(format!(
                "points must be (N, 3), got {shape:?}"
            )));
        }
        Ok(p)
    }
}

fn contiguous<'a, T>(r: Result<&'a [T], numpy::AsSliceError>, name: &str) -> PyResult<&'a [T]> {
    r.map_err(|_| PyValueError::new_err(format!("{name} must be C-contiguous")))
}

/// Dispatch a kernel generic over the point dtype.
macro_rules! with_points {
    ($points:expr, |$p:ident| $body:expr) => {
        match &$points {
            Points::F32(a) => {
                let $p = contiguous(a.as_slice(), "points")?;
                $body
            }
            Points::F64(a) => {
                let $p = contiguous(a.as_slice(), "points")?;
                $body
            }
        }
    };
}

fn rows<'py, T: numpy::Element>(
    py: Python<'py>,
    flat: Vec<T>,
    width: usize,
) -> PyResult<Bound<'py, PyArray2<T>>> {
    let n = flat.len() / width;
    flat.into_pyarray(py).reshape([n, width])
}

type Tables<'py> = (
    Bound<'py, PyArray1<i64>>,
    Bound<'py, PyArray1<i64>>,
    Bound<'py, PyArray1<i64>>,
    Bound<'py, PyArray1<i64>>,
    Bound<'py, PyArray2<i64>>,
);

/// Sorted-edge tables of `faces` (int64 `(M, 3)`): `(order, inv, start, counts, uniq)`.
#[pyfunction]
fn edge_tables<'py>(py: Python<'py>, faces: PyReadonlyArray2<'py, i64>) -> PyResult<Tables<'py>> {
    let f = faces_slice(&faces)?;
    let t = py
        .detach(|| kernels::EdgeTables::build(f))
        .map_err(value_err)?;
    Ok((
        t.order.into_pyarray(py),
        t.inv.into_pyarray(py),
        t.start.into_pyarray(py),
        t.counts.into_pyarray(py),
        rows(py, t.uniq, 2)?,
    ))
}

/// Face components through shared slot ids (`inv` int64 `(3M,)`), labels by first appearance.
#[pyfunction]
fn components_from_slots<'py>(
    py: Python<'py>,
    m: usize,
    inv: PyReadonlyArray1<'py, i64>,
) -> PyResult<Bound<'py, PyArray1<i64>>> {
    let inv = contiguous(inv.as_slice(), "inv")?;
    let labels = py
        .detach(|| kernels::components_from_slots(m, inv))
        .map_err(value_err)?;
    Ok(labels.into_pyarray(py))
}

/// Topology audit: the dict of `frontier_prep.ops.mesh.topology` (same keys and types).
#[pyfunction]
fn topology<'py>(
    py: Python<'py>,
    points: &Bound<'py, PyAny>,
    faces: PyReadonlyArray2<'py, i64>,
) -> PyResult<Bound<'py, PyDict>> {
    let pts = Points::extract(points)?;
    let f = faces_slice(&faces)?;
    let d = PyDict::new(py);
    if f.is_empty() {
        let n_points = match &pts {
            Points::F32(a) => a.shape()[0],
            Points::F64(a) => a.shape()[0],
        };
        d.set_item("n_points", n_points)?;
        d.set_item("n_faces", 0)?;
        return Ok(d);
    }
    let a = with_points!(pts, |p| py.detach(|| kernels::topology(p, f))).map_err(value_err)?;
    d.set_item("n_points", a.n_points)?;
    d.set_item("n_faces", a.n_faces)?;
    d.set_item("n_edges", a.n_edges)?;
    d.set_item("open_edges", a.open_edges)?;
    d.set_item("nonmanifold_edges", a.nonmanifold_edges)?;
    d.set_item("inconsistent_edges", a.inconsistent_edges)?;
    d.set_item("degenerate_faces", a.degenerate_faces)?;
    d.set_item("components", a.components)?;
    d.set_item("euler", a.euler)?;
    d.set_item("genus_estimate", a.genus_estimate())?;
    d.set_item("watertight", a.watertight())?;
    d.set_item("oriented", a.oriented())?;
    d.set_item("area", a.area)?;
    d.set_item("boundary_length", a.boundary_length)?;
    d.set_item("bounds", a.bounds.to_vec())?;
    d.set_item("signed_volume", a.signed_volume)?;
    Ok(d)
}

/// Per-face areas (float64 `(M,)`), the values of `SurfaceMesh.face_areas()`.
#[pyfunction]
fn face_areas<'py>(
    py: Python<'py>,
    points: &Bound<'py, PyAny>,
    faces: PyReadonlyArray2<'py, i64>,
) -> PyResult<Bound<'py, PyArray1<f64>>> {
    let pts = Points::extract(points)?;
    let f = faces_slice(&faces)?;
    let areas =
        with_points!(pts, |p| py.detach(|| kernels::face_areas(p, f))).map_err(value_err)?;
    Ok(areas.into_pyarray(py))
}

type MergedArrays<'py> = (
    Bound<'py, PyArray2<f32>>,
    Bound<'py, PyArray2<i32>>,
    Bound<'py, PyArray1<i64>>,
);

/// Coincident-vertex merge: `(points float32 (K, 3), faces int32 (M', 3), point_map int64
/// (N,))`, or `None` when the quantised keys are not representable (the caller then uses the
/// Python reference, whose float-to-int conversion is platform-defined for such input).
#[pyfunction]
#[pyo3(signature = (points, faces, tol=0.0))]
fn merge_vertices<'py>(
    py: Python<'py>,
    points: &Bound<'py, PyAny>,
    faces: PyReadonlyArray2<'py, i64>,
    tol: f64,
) -> PyResult<Option<MergedArrays<'py>>> {
    let pts = Points::extract(points)?;
    let f = faces_slice(&faces)?;
    let merged = with_points!(pts, |p| py.detach(|| kernels::merge_vertices(p, f, tol)))
        .map_err(value_err)?;
    let Some(m) = merged else {
        return Ok(None);
    };
    Ok(Some((
        rows(py, m.points, 3)?,
        rows(py, m.faces, 3)?,
        m.point_map.into_pyarray(py),
    )))
}

/// Consistent orientation: `(faces int32 (M, 3), n_flipped)`.
#[pyfunction]
fn orient_consistently<'py>(
    py: Python<'py>,
    faces: PyReadonlyArray2<'py, i64>,
) -> PyResult<(Bound<'py, PyArray2<i32>>, usize)> {
    let f = faces_slice(&faces)?;
    let (out, n) = py
        .detach(|| kernels::orient_consistently(f))
        .map_err(value_err)?;
    Ok((rows(py, out, 3)?, n))
}

/// Mask (bool `(M,)`) of faces whose vertex set repeats an earlier face's.
#[pyfunction]
fn duplicate_faces<'py>(
    py: Python<'py>,
    faces: PyReadonlyArray2<'py, i64>,
) -> PyResult<Bound<'py, PyArray1<bool>>> {
    let f = faces_slice(&faces)?;
    let dup = py
        .detach(|| kernels::duplicate_faces(f))
        .map_err(value_err)?;
    Ok(dup.into_pyarray(py))
}

fn scaled<'py, T: numpy::Element + kernels::scale::Widen>(
    py: Python<'py>,
    x: &PyReadonlyArrayDyn<'py, T>,
    factor: f64,
) -> PyResult<Bound<'py, PyArrayDyn<f32>>> {
    let data = contiguous(x.as_slice(), "x")?;
    let out = py.detach(|| kernels::scale_block(data, factor));
    out.into_pyarray(py).reshape(x.shape().to_vec())
}

/// `float32(float64(x) * factor)` for a float32 or float64 array of any shape.
#[pyfunction]
fn scale_block<'py>(
    py: Python<'py>,
    x: &Bound<'py, PyAny>,
    factor: f64,
) -> PyResult<Bound<'py, PyArrayDyn<f32>>> {
    if let Ok(a) = x.cast::<PyArrayDyn<f32>>() {
        scaled(py, &a.try_readonly().map_err(value_err)?, factor)
    } else if let Ok(a) = x.cast::<PyArrayDyn<f64>>() {
        scaled(py, &a.try_readonly().map_err(value_err)?, factor)
    } else {
        Err(PyTypeError::new_err(
            "x must be a float32 or float64 numpy array",
        ))
    }
}

/// Number of threads the kernels use (`RAYON_NUM_THREADS`, default: all cores). The outputs
/// do not depend on it.
#[pyfunction]
fn num_threads() -> usize {
    rayon::current_num_threads()
}

pub(crate) fn module<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyModule>> {
    let m = PyModule::new(py, "frontier_native.prep")?;
    m.add("KERNELS_VERSION", kernels::KERNELS_VERSION)?;
    m.add("SPEC_REVISION", kernels::SPEC_REVISION)?;
    m.add_function(wrap_pyfunction!(edge_tables, &m)?)?;
    m.add_function(wrap_pyfunction!(components_from_slots, &m)?)?;
    m.add_function(wrap_pyfunction!(topology, &m)?)?;
    m.add_function(wrap_pyfunction!(face_areas, &m)?)?;
    m.add_function(wrap_pyfunction!(merge_vertices, &m)?)?;
    m.add_function(wrap_pyfunction!(orient_consistently, &m)?)?;
    m.add_function(wrap_pyfunction!(duplicate_faces, &m)?)?;
    m.add_function(wrap_pyfunction!(scale_block, &m)?)?;
    m.add_function(wrap_pyfunction!(num_threads, &m)?)?;
    Ok(m)
}
