/*
 * This file and its contents are licensed under the BSL 1.1 License.
 * Please see the included NOTICE for copyright information and
 * LICENSE-BSL for a copy of the license.
 */

use std::collections::HashMap;

use serde::Serialize;
use serde_json::json;

use crate::error;

use rustpython_parser::{
    ast::{ExpressionType, Located, Number, StatementType, StringGroup, Varargs},
    parser,
};
#[derive(Serialize)]
pub struct MainArgSignature {
    star_args: bool,
    star_kwargs: bool,
    args: Vec<Arg>,
}

#[derive(Serialize)]
#[serde(rename_all(serialize = "lowercase"))]
enum Typ {
    Str,
    Int,
    Float,
    Bool,
    Dict,
    List,
    Unknown,
}

#[derive(Serialize)]
struct Arg {
    name: String,
    typ: Typ,
    default: Option<serde_json::Value>,
    has_default: bool,
}

pub fn parse(code: &str) -> error::Result<MainArgSignature> {
    let ast = parser::parse_program(code)
        .map_err(|e| error::Error::ExecutionErr(format!("Error parsing code: {}", e.to_string())))?
        .statements;
    let param = ast.into_iter().find_map(|x| match x {
        Located {
            location: _,
            node:
                StatementType::FunctionDef {
                    is_async: _,
                    name,
                    args,
                    body: _,
                    decorator_list: _,
                    returns: _,
                },
        } if &name == "main" => Some(*args),
        _ => None,
    });
    if let Some(params) = param {
        //println!("{:?}", params);
        let def_arg_start = params.args.len() - params.defaults.len();
        Ok(MainArgSignature {
            star_args: params.vararg != Varargs::None,
            star_kwargs: params.vararg != Varargs::None,
            args: params
                .args
                .into_iter()
                .enumerate()
                .map(|(i, x)| {
                    let default = if i >= def_arg_start {
                        to_value(&params.defaults[i - def_arg_start].node)
                    } else {
                        None
                    };
                    Arg {
                        name: x.arg,
                        typ: x.annotation.map_or(Typ::Unknown, |e| match *e {
                            Located {
                                location: _,
                                node: ExpressionType::Identifier { name },
                            } => match name.as_ref() {
                                "str" => Typ::Str,
                                "float" => Typ::Float,
                                "int" => Typ::Int,
                                "bool" => Typ::Bool,
                                "dict" => Typ::Dict,
                                "list" => Typ::List,
                                _ => Typ::Unknown,
                            },
                            _ => Typ::Unknown,
                        }),
                        has_default: default.is_some(),
                        default,
                    }
                })
                .collect(),
        })
    } else {
        Err(error::Error::ExecutionErr(
            "main function was not findable".to_string(),
        ))
    }
}

fn to_value(et: &ExpressionType) -> Option<serde_json::Value> {
    match et {
        ExpressionType::String {
            value: StringGroup::Constant { value },
        } => Some(json!(value)),
        ExpressionType::Number { value } => match value {
            Number::Integer { value } => Some(json!(value.to_string().parse::<i64>().unwrap())),
            Number::Float { value } => Some(json!(value)),
            _ => None,
        },
        ExpressionType::Dict { elements } => {
            let v = elements
                .into_iter()
                .map(|(k, v)| {
                    let key = k
                        .as_ref()
                        .and_then(|x| to_value(&x.node))
                        .and_then(|x| match x {
                            serde_json::Value::String(s) => Some(s),
                            _ => None,
                        })
                        .unwrap_or_else(|| "no_key".to_string());
                    (key, to_value(&v.node))
                })
                .collect::<HashMap<String, _>>();
            Some(json!(v))
        }
        ExpressionType::List { elements } => {
            let v = elements
                .into_iter()
                .map(|x| to_value(&x.node))
                .collect::<Vec<_>>();
            Some(json!(v))
        }
        ExpressionType::None => Some(json!(null)),

        _ => None,
    }
}
#[cfg(test)]
mod tests {

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_parse() -> anyhow::Result<()> {
        //let code = "print(2 + 3, fd=sys.stderr)";
        let code = "

import os

def main(test1: str, name: str = \"Nicolas Bourbaki\", test: str = \"test2\"):

	print(f\"Hello World and a warm welcome especially to {name}\")
	print(\"The env variable at `all/pretty_secret`: \", os.environ.get(\"ALL_PRETTY_SECRET\"))
	return {\"len\": len(name), \"splitted\": name.split() }

";
        println!("{}", serde_json::to_string(&parse(code)?)?);

        Ok(())
    }
}
