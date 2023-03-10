module Dhall.Secret.Type where
import           Data.Void  (Void)
import           Dhall.Core (Expr)
import           Dhall.Src  (Src)
import           Dhall.TH

secretTypes :: Expr Src Void
secretTypes = [dhall|./src/Type.dhall|]
