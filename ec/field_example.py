from field import Zp


def example_field():
    print('field module example:\n')

    # get Z/5
    F = Zp(5)
    # get all elements at once
    print(F, ' = ', F.get_elements())
    # or like iterator
    [print(elem, end=' ') for elem in F]
    print('')
    # or
    print(list(F))
    print('')
    # or reversed
    [print(elem, end=' ') for elem in reversed(F)]
    print('')
    # get 3 from Z/5
    print('F(3) =', F(3))
    # or like this
    print('F[3] =', F[3])
    # get the ord of Z/5
    print('ord(%s) =' % F, len(F))
    # some math operations
    print('3 + 4 (mod 5) =', F(3) + F(4))
    print('3 * 4 (mod 5) =', F(3) * F(4))
    print('3 / 4 (mod 5) =', F(3) / F(4))
    print('3^-1 (mod 5) =', ~F(3))
    print('3^10 (mod 5) =', F(3) ** 10)
    # get int value from element
    print('F(3).val =', F(3).val)
    # or this way
    print('int(F(3)) =', int(F(3)))


if __name__ == "__main__":
    example_field()
